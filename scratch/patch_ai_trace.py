import sys
import re

def add_logs():
    # 1. sentinel_ai_page.py
    with open('gui/pages/sentinel_ai_page.py', 'r', encoding='utf-8') as f:
        gui = f.read()
    
    gui = gui.replace(
        '        def _process():',
        '''        def _process():
            import time, logging
            log = logging.getLogger("sentinel.gui")
            log.info(f"AI_GUI_REQUEST_START | TS: {time.time()} | REQ_ID: {current_req}")'''
    )
    
    gui = gui.replace(
        '                self.after(0, self._on_message_received, thinking_start, reply, current_req)',
        '''                log.info(f"AI_GUI_CALLBACK | REQ_ID: {current_req} | SUCCESS: {bool(reply)}")
                self.after(0, self._on_message_received, thinking_start, reply, current_req)'''
    )
    
    gui = gui.replace(
        '    def _on_message_received(self, start_idx: str, reply: str, req_id: int = -1):',
        '''    def _on_message_received(self, start_idx: str, reply: str, req_id: int = -1):
        import time, logging
        logging.getLogger("sentinel.gui").info(f"AI_GUI_REQUEST_END | TS: {time.time()} | REQ_ID: {req_id}")'''
    )
    
    with open('gui/pages/sentinel_ai_page.py', 'w', encoding='utf-8') as f:
        f.write(gui)
        
    # 2. sentinel_ai.py
    with open('ai/sentinel_ai.py', 'r', encoding='utf-8') as f:
        ai = f.read()
    
    ai = ai.replace(
        '        return self.provider.generate(prompt, context_str)',
        '''        import logging
        log = logging.getLogger(__name__)
        log.info(f"AI_PROVIDER_SELECTED | PROVIDER: {self.provider.get_name()}")
        return self.provider.generate(prompt, context_str)'''
    )
    
    with open('ai/sentinel_ai.py', 'w', encoding='utf-8') as f:
        f.write(ai)
        
    # 3. provider.py
    with open('ai/provider.py', 'r', encoding='utf-8') as f:
        prov = f.read()
    
    prov = prov.replace(
        '    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Tuple[bool, str]:',
        '''    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Tuple[bool, str]:
        import time, logging
        log = logging.getLogger(__name__)
        start_ts = time.time()
        log.info(f"AI_PROVIDER_GENERATE_START | TS: {start_ts} | URL: {getattr(self, 'backend_url', 'UNKNOWN')} | TIMEOUT: 35")'''
    )
    
    # We need to replace the returns in generate with logging
    # Actually, a simpler way is to wrap generate. But let's just log before the post.
    prov = prov.replace(
        '        try:\n            r = requests.post(url, json=payload, timeout=35)',
        '''        try:
            log.info("AI_PROVIDER_GENERATE_POST_START")
            r = requests.post(url, json=payload, timeout=35)
            log.info(f"AI_PROVIDER_GENERATE_END | ELAPSED: {time.time()-start_ts:.3f}s | STATUS: {r.status_code}")'''
    )
    
    # Catch timeout and log
    prov = prov.replace(
        '        except requests.exceptions.Timeout:',
        '''        except requests.exceptions.Timeout:
            log.error(f"AI_PROVIDER_GENERATE_END | ELAPSED: {time.time()-start_ts:.3f}s | ERROR: Timeout")'''
    )
    prov = prov.replace(
        '        except Exception as e:',
        '''        except Exception as e:
            log.error(f"AI_PROVIDER_GENERATE_END | ELAPSED: {time.time()-start_ts:.3f}s | ERROR: {str(e)}")'''
    )
    
    with open('ai/provider.py', 'w', encoding='utf-8') as f:
        f.write(prov)
        
    print("Injected tracing logs")

add_logs()
