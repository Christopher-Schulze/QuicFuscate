use quicfuscate::privilege::{
    drop_privileges_resolved, enable_no_new_privileges, harden_runtime_worker_thread,
    prove_root_cannot_be_regained, resolve_identity, verify_process_privilege_state,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let usage = "usage: qf-privilege-probe USER_OR_UID GROUP_OR_GID [--threads COUNT|--tokio-threads COUNT]";
    let user = arguments.next().ok_or(usage)?;
    let group = arguments.next().ok_or(usage)?;
    let (thread_count, tokio_threads) = match arguments.next() {
        None => (0, false),
        Some(flag) if flag == "--threads" => {
            (arguments.next().ok_or(usage)?.parse::<usize>()?, false)
        }
        Some(flag) if flag == "--tokio-threads" => {
            (arguments.next().ok_or(usage)?.parse::<usize>()?, true)
        }
        Some(_) => return Err(usage.into()),
    };
    if arguments.next().is_some() {
        return Err(usage.into());
    }

    enable_no_new_privileges()?;
    let identity = resolve_identity(&user, &group)?;
    let runtime = if tokio_threads {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.worker_threads(thread_count).enable_all().on_thread_start(|| {
            harden_runtime_worker_thread()
                .unwrap_or_else(|error| panic!("Tokio worker hardening failed: {error}"));
        });
        let runtime = builder.build()?;
        runtime.block_on(async {
            let mut workers = Vec::with_capacity(thread_count);
            for _ in 0..thread_count {
                workers.push(tokio::spawn(async { tokio::task::yield_now().await }));
            }
            for worker in workers {
                worker.await.expect("Tokio probe worker failed");
            }
        });
        Some(runtime)
    } else {
        None
    };
    let standard_thread_count = if tokio_threads { 0 } else { thread_count };
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ready = std::sync::Arc::new(std::sync::Barrier::new(standard_thread_count + 1));
    let mut workers = Vec::with_capacity(standard_thread_count);
    for _ in 0..standard_thread_count {
        let worker_stop = stop.clone();
        let worker_ready = ready.clone();
        workers.push(std::thread::spawn(move || {
            worker_ready.wait();
            while !worker_stop.load(std::sync::atomic::Ordering::Acquire) {
                std::thread::yield_now();
            }
        }));
    }
    ready.wait();
    let report = drop_privileges_resolved(&identity)?;
    let verified_threads = verify_process_privilege_state(&identity)?;
    eprintln!("PRIVILEGE_PROBE_STATE threads_verified={verified_threads}");
    if let Some(runtime) = runtime {
        runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    } else {
        stop.store(true, std::sync::atomic::Ordering::Release);
        for worker in workers {
            worker.join().map_err(|_| "privilege probe worker panicked")?;
        }
    }
    prove_root_cannot_be_regained(&identity)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
