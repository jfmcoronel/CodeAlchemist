module Fuzzer.Fuzzer

open System
open AST.CodeGen
open Common
open Common.Utils
open Analyzer

let mkGenerate iBlk sPool gPool (rnd: Random) pBlk =
  let genStmt sb ctx =
    let struct (stmt, rMap, scope, dMap, post) =
      Selector.pickBrick rnd sPool ctx
    stmtItemToCode rMap sb stmt
    Context.update ctx scope dMap post

  let rec generate sb i d ctx =
    printfn "i = %d" i
    printfn "%A\n" ctx
    if i > 0 then
      if d > 0 && rnd.Next (100) < pBlk then
        match genBlk sb (d - 1) ctx with
        | Some ctx -> generate sb (i - 1) d ctx
        | None -> generate sb i d ctx
      else genStmt sb ctx |> generate sb (i - 1) d
    else ctx

  and genBlk sb d ctx0 =
    let ctx = Selector.pickCtx rnd ctx0
    let selectedGuard = Selector.pickGuard rnd gPool ctx
    printfn "selected guard: %A\n" selectedGuard
    printfn "inner context 1: %A\n" ctx
    match selectedGuard with
    | Some (struct (guard, rMap, scope, dMap, post)) ->
      let ctx = Context.initBlk ctx guard scope dMap post
      printfn "inner context 2: %A\n" ctx
      CodeBrick.guardToCodeInit rMap sb guard
      let ret = generate sb (rnd.Next (1, iBlk)) d ctx
      CodeBrick.guardToCodeFini rMap sb guard
      Context.finiBlk guard ctx0 ret |> Some
    | None ->
      printfn "none matched"
      None

  generate

let fuzzMain conf sPool gPool rndSeed = async {
  let rnd = new Random (rndSeed)
  let iMax = conf.IterMax
  let dMax = conf.DepthMax
  let prefix = sprintf "%s/%d" conf.TmpDir rndSeed
  let bugPrefix = sprintf "%s/%d" conf.BugDir rndSeed
  let exec = Executor.getAsyncExec conf conf.TmpDir
  let isBug = Oracle.getOracle conf.Engine
  let generate = mkGenerate conf.IterBlk sPool gPool rnd conf.ProbBlk

  let mutable idx = 0
  while true do
    let fname = sprintf "%s-%d.js" prefix idx
    let sb = new SB ()
    generate sb iMax dMax Context.empty |> ignore
    sb.ToString() |> writeFile fname |> ignore
    let! ret = exec fname
    if isBug ret |> not then renameFile fname fname  // Do not delete intermediate files
    else renameFile fname (sprintf "%s-%d.js" bugPrefix idx)
    idx <- idx + 1
    Console.ReadKey() |> ignore
}

let fuzz conf bricks =
  let loop = Pool.initPools bricks ||> fuzzMain conf
  Random.initSeed conf.Jobs
  |> Array.map loop
  |> Async.Parallel
  |> Async.RunSynchronously
  |> ignore
