import sys
with open('scanner/scan_engine.py', 'r', encoding='utf-8') as f:
    text = f.read()

target = '''        try:
            # Determine scan scope
            scan_paths = self._determine_scan_paths(scan_type, custom_paths)
            if not scan_paths:
                log.error("No valid scan paths determined")
                result.state = ScanState.SCAN_INCOMPLETE
                result.error_message = "No valid scan paths"
                return result

            log.info("Scan scope: %d paths", len(scan_paths))'''

replacement = '''        import uuid
        scan_id = str(uuid.uuid4())
        setattr(result, '_scan_id', scan_id)
        log.info(f"SCAN_START | ID: {scan_id} | TS: {scan_start} | MODE: {scan_type.value}")

        try:
            # Determine scan scope
            scan_paths = self._determine_scan_paths(scan_type, custom_paths)
            if not scan_paths:
                log.error("No valid scan paths determined")
                result.state = ScanState.SCAN_INCOMPLETE
                result.error_message = "No valid scan paths"
                return result

            log.info(f"Scan scope: {len(scan_paths)} paths | RESOLVED: {[str(p) for p in scan_paths]}")'''

target_crlf = target.replace('\n', '\r\n')
replacement_crlf = replacement.replace('\n', '\r\n')

if target in text:
    with open('scanner/scan_engine.py', 'w', encoding='utf-8') as f:
        f.write(text.replace(target, replacement))
    print('SUCCESS 1')
elif target_crlf in text:
    with open('scanner/scan_engine.py', 'w', encoding='utf-8') as f:
        f.write(text.replace(target_crlf, replacement_crlf))
    print('SUCCESS 1 (CRLF)')
else:
    print('FAILED 1')

# Now inject FILESYSTEM_SCAN_START, FILESYSTEM_SCAN_END etc.
target2 = '''    def _scan_filesystem(self, paths: List[Path], result: ScanResult) -> bool:'''
replacement2 = '''    def _scan_filesystem(self, paths: List[Path], result: ScanResult) -> bool:
        log.info(f"FILESYSTEM_SCAN_START")'''

target3 = '''            log.info("Filesystem scan complete: %d files, %d dirs",
                    stats.files_inspected, stats.directories_inspected)
            return True'''
replacement3 = '''            log.info("Filesystem scan complete: %d files, %d dirs",
                    stats.files_inspected, stats.directories_inspected)
            log.info(f"FILESYSTEM_SCAN_END")
            return True'''

target4 = '''    def _scan_processes(self, result: ScanResult) -> bool:'''
replacement4 = '''    def _scan_processes(self, result: ScanResult) -> bool:
        log.info(f"LIVE_PROCESS_SCAN_START")'''

target5 = '''            log.info("Process scan complete: %d processes", result.processes_analyzed)
            return True'''
replacement5 = '''            log.info("Process scan complete: %d processes", result.processes_analyzed)
            log.info(f"LIVE_PROCESS_SCAN_END")
            return True'''

target6 = '''    def _run_ml_analysis(self, result: ScanResult) -> bool:'''
replacement6 = '''    def _run_ml_analysis(self, result: ScanResult) -> bool:
        log.info(f"ML_ANALYSIS_START")'''

target7 = '''            log.info("[OK] ML analysis complete: %s (%.4f)", threat_level, probability)
            return True'''
replacement7 = '''            log.info("[OK] ML analysis complete: %s (%.4f)", threat_level, probability)
            log.info(f"ML_ANALYSIS_END")
            return True'''

target8 = '''        # Finalize stats
        result.elapsed_seconds = time.time() - scan_start'''
replacement8 = '''        # Finalize stats
        result.elapsed_seconds = time.time() - scan_start
        scan_id = getattr(result, '_scan_id', 'UNKNOWN')
        log.info(f"SCAN_COMPLETE | ID: {scan_id} | DURATION: {result.elapsed_seconds:.3f}s | FILES: {result.files_inspected} | DIRS: {result.directories_inspected} | PROCS: {result.processes_analyzed} | PROB: {result.ml_probability} | STATE: {result.state.value}")'''

# Add all replacements
def replace_all(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    pairs = [
        (target2, replacement2),
        (target3, replacement3),
        (target4, replacement4),
        (target5, replacement5),
        (target6, replacement6),
        (target7, replacement7),
        (target8, replacement8),
    ]
    
    for t, r in pairs:
        t_crlf = t.replace('\n', '\r\n')
        r_crlf = r.replace('\n', '\r\n')
        if t in content:
            content = content.replace(t, r)
        elif t_crlf in content:
            content = content.replace(t_crlf, r_crlf)
        else:
            print(f"FAILED TO FIND: {t[:40]}")
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

replace_all('scanner/scan_engine.py')
print("Finished replacements")
