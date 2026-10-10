import abc
import json
import logging
import requests
import time
from typing import Optional, Tuple

log = logging.getLogger(__name__)

class AIProvider(abc.ABC):
    @abc.abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None, scan_context: Optional[dict] = None) -> Tuple[bool, str]:
        pass

    @abc.abstractmethod
    def is_available(self) -> Tuple[str, str]:
        pass
        
    @abc.abstractmethod
    def get_name(self) -> str:
        pass

class OllamaProvider(AIProvider):
    def __init__(self, host="http://localhost:11434", model="llama3"):
        self.host = host
        self.model = model
        
    def get_name(self) -> str:
        return f"Local (Ollama: {self.model})"
        
    def is_available(self) -> Tuple[str, str]:
        try:
            r = requests.get(f"{self.host}/api/tags", timeout=3)
            if r.status_code == 200:
                models = r.json().get("models", [])
                if any(m.get("name", "").startswith(self.model) for m in models):
                    # Do a tiny inference test
                    gen_r = requests.post(f"{self.host}/api/generate", json={"model": self.model, "prompt": "Reply only with: OK", "stream": False}, timeout=10)
                    if gen_r.status_code == 200:
                        return "READY", "Local model is available and responding."
                    return "ERROR", f"Model found but inference failed: {gen_r.status_code}"
                return "MODEL_NOT_FOUND", f"Model {self.model} not installed."
            return "ERROR", f"Ollama API returned {r.status_code}"
        except requests.exceptions.Timeout:
            return "TIMEOUT", "Connection to Ollama timed out."
        except requests.exceptions.ConnectionError:
            return "OFFLINE", "Cannot connect to Ollama. Is it running?"
        except Exception as e:
            return "ERROR", str(e)
            
    def generate(self, prompt: str, system_prompt: Optional[str] = None, scan_context: Optional[dict] = None) -> Tuple[bool, str]:
        try:
            url = f"{self.host}/api/generate"
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False
            }
            if system_prompt:
                payload["system"] = system_prompt
                
            r = requests.post(url, json=payload, timeout=60)
            r.encoding = 'utf-8'
            if r.status_code == 200:
                return True, r.json().get("response", "").strip()
            return False, f"HTTP {r.status_code}: {r.text}"
        except Exception as e:
            return False, str(e)

class GeminiProvider(AIProvider):
    MODELS = ["gemini-3.6-flash", "gemini-3.5-flash", "gemini-3.1-flash-lite"]

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base = "https://generativelanguage.googleapis.com/v1beta/models"
        self.active_model = self.MODELS[0]
        self._update_url()

    def _update_url(self):
        self.url = f"{self.base}/{self.active_model}:generateContent?key={self.api_key}"

    def get_name(self) -> str:
        return f"Cloud (Gemini {self.active_model})"

    def is_available(self) -> Tuple[str, str]:
        if not self.api_key or len(self.api_key) < 10:
            return "NOT_CONFIGURED", "API Key is missing or invalid."
            
        for model in self.MODELS:
            self.active_model = model
            self._update_url()
            
            # Retry the health check once in case of a transient 503 during startup
            for attempt in range(2):
                try:
                    r = requests.post(
                        self.url,
                        headers={"Content-Type": "application/json"},
                        json={"contents": [{"parts": [{"text": "Reply only with: OK"}]}]},
                        timeout=12
                    )
                    if r.status_code == 200:
                        return "READY", "Connection successful."
                    elif r.status_code in (503, 429, 404, 500, 502, 504):
                        if attempt == 0 and r.status_code not in (404, 429):
                            time.sleep(2)
                            continue
                        log.warning(f"Model {self.active_model} unavailable: HTTP {r.status_code}")
                        break
                    elif r.status_code in (400, 403, 401):
                        return "AUTHENTICATION_ERROR", "API Key is invalid or unauthorized."
                    else:
                        return "ERROR", f"HTTP {r.status_code}: {r.text[:100]}"
                except requests.exceptions.Timeout:
                    log.warning(f"Model {self.active_model} timeout during health check")
                    break
                except requests.exceptions.ConnectionError:
                    return "OFFLINE", "No internet connection to reach Gemini API."
                except Exception as e:
                    return "ERROR", str(e)
                    
        return "MODEL_UNAVAILABLE", "All configured AI models are temporarily overloaded or unavailable. Please try again shortly."

    def generate(self, prompt: str, system_prompt: Optional[str] = None, scan_context: Optional[dict] = None) -> Tuple[bool, str]:
        if not self.api_key:
            return False, "API Key not configured."

        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}]
        }
        if system_prompt:
            payload["systemInstruction"] = {"parts": [{"text": system_prompt}]}

        start_idx = self.MODELS.index(self.active_model) if self.active_model in self.MODELS else 0
        last_error = ""
        
        for i in range(start_idx, len(self.MODELS)):
            self.active_model = self.MODELS[i]
            self._update_url()
            
            # 2 retries with exponential backoff: 2s, 4s
            max_retries = 2
            base_delay = 2.0

            for attempt in range(max_retries + 1):
                try:
                    r = requests.post(self.url, headers=headers, json=payload, timeout=60)
                    r.encoding = 'utf-8'

                    if r.status_code == 200:
                        data = r.json()
                        try:
                            text = data["candidates"][0]["content"]["parts"][0]["text"]
                            return True, text.strip()
                        except (KeyError, IndexError):
                            return False, "Malformed response from Gemini API."

                    if r.status_code in (429, 500, 502, 503, 504, 404):
                        last_error = f"HTTP {r.status_code}: The configured AI model is currently experiencing high demand. Please try again shortly."
                        if attempt < max_retries and r.status_code not in (404, 429):
                            log.warning(f"Gemini API transient error HTTP {r.status_code}. Retrying in {base_delay}s...")
                            time.sleep(base_delay)
                            base_delay *= 2
                            continue
                        else:
                            log.warning(f"Model {self.active_model} failed generation: HTTP {r.status_code}")
                            break

                    return False, f"HTTP {r.status_code}: {r.text[:400]}"

                except requests.exceptions.Timeout:
                    last_error = "SENTINELAI TIMEOUT: The AI provider did not respond within the expected time."
                    if attempt < max_retries:
                        time.sleep(base_delay)
                        base_delay *= 2
                        continue
                    log.warning(f"Model {self.active_model} timeout during generation")
                    break
                except requests.exceptions.ConnectionError:
                    return False, "OFFLINE: Cannot reach the AI provider. Check your internet connection."
                except Exception as e:
                    err_str = str(e)
                    if self.api_key and self.api_key in err_str:
                        err_str = err_str.replace(self.api_key, "[REDACTED]")
                    return False, f"Error: {err_str}"
                    
        return False, last_error or "All configured AI models are unavailable."
class SentinelBackendProvider(AIProvider):
    def __init__(self, backend_url: str):
        self.backend_url = backend_url.rstrip("/")
        self.active_model = "SentinelML AI"

    def get_name(self) -> str:
        return "SentinelML AI Cloud"

    def is_available(self) -> Tuple[str, str]:
        if not self.backend_url:
            return "NOT_CONFIGURED", "Backend URL is missing."
            
        try:
            r = requests.get(f"{self.backend_url}/health", timeout=60)
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "ok":
                    return "READY", "Connection successful."
            return "ERROR", f"Backend returned {r.status_code}"
        except requests.exceptions.Timeout:
            return "TIMEOUT", "SentinelML AI service did not respond within 30 seconds."
        except requests.exceptions.ConnectionError:
            return "OFFLINE", "Unable to reach SentinelML AI service."
        except Exception as e:
            return "ERROR", str(e)

    def generate(self, prompt: str, system_prompt: Optional[str] = None, scan_context: Optional[dict] = None) -> Tuple[bool, str]:
        import time, logging
        log = logging.getLogger(__name__)
        start_ts = time.time()
        log.info(f"AI_PROVIDER_GENERATE_START | TS: {start_ts} | URL: {getattr(self, 'backend_url', 'UNKNOWN')}")
        if not self.backend_url:
            return False, "Backend URL not configured."
            
        url = f"{self.backend_url}/api/v1/ai/chat"
        payload = {
            "message": prompt
        }
        if scan_context:
            payload["context"] = scan_context
        if system_prompt:
            payload["system_instructions"] = system_prompt
        
        # Render free-tier occasionally returns 500/502/503 during or just after
        # cold-start warm-up. Retry up to 1 time with 5s backoff before failing.
        MAX_RETRIES = 1
        RETRY_DELAY = 5.0
        TRANSIENT_CODES = {500, 502, 503, 504}

        # Bulletproof safety cap to strictly prevent HTTP 422 from backend
        if "message" in payload and len(payload["message"]) > 3900:
            payload["message"] = payload["message"][:3900]

        last_error = ""
        for attempt in range(MAX_RETRIES + 1):
            if scan_context is not None and attempt == 0:
                print("\nFINAL PAYLOAD METADATA:")
                msg = payload.get("message", "")
                print(f"- message repr: {repr(msg)}")
                print(f"- message length: {len(msg)}")
                print(f"- context type: {type(scan_context)}")
                print(f"- context keys: {list(scan_context.keys()) if scan_context else []}")
                sys_inst = payload.get("system_instructions", "")
                print(f"- system_instructions length: {len(sys_inst) if sys_inst else 0}")
                print(f"- history length: Not present in payload")
                try:
                    import json
                    ser = json.dumps(payload)
                    print("- JSON serialization success: True")
                    print(f"- serialized JSON length: {len(ser)}")
                except Exception as e:
                    print(f"- JSON serialization success: False (Error: {e})")
                print("==================================\n")
            try:
                r = requests.post(url, json=payload, timeout=90)
                r.encoding = "utf-8"
                if r.status_code == 422:
                    print(f"\nACTUAL 422 BODY:\n{r.text}")
                    try:
                        errs = r.json().get("detail", [])
                        locs = [e.get("loc", []) for e in errs]
                        msgs = [e.get("msg", "") for e in errs]
                        print(f"VALIDATION LOC:\n{locs}")
                        print(f"VALIDATION MESSAGE:\n{msgs}")
                    except:
                        pass
                    return False, f"422 Validation Error"
                elapsed = time.time() - start_ts
                log.info(f"AI_PROVIDER_GENERATE_END | ELAPSED: {elapsed:.3f}s | STATUS: {r.status_code} | ATTEMPT: {attempt+1}")

                if r.status_code == 200:
                    data = r.json()
                    if data.get("success"):
                        return True, data.get("response", "")
                    return False, data.get("response", "Unknown error from backend.")

                if r.status_code in (401, 403):
                    return False, "AI service authentication failed."
                if r.status_code == 422:
                    log.error(f"HTTP 422 Exact Response: {r.text}")
                    try:
                        errs = [e.get("loc", []) for e in r.json().get("detail", [])]
                        return False, f"422 Validation Error on fields: {errs}"
                    except:
                        return False, f"422 Validation Error: {r.text}"
                if r.status_code == 429:
                    return False, "SentinelML AI service is temporarily busy. Please try again later."

                if r.status_code in TRANSIENT_CODES:
                    last_error = "SentinelML AI service encountered a temporary error."
                    if attempt < MAX_RETRIES:
                        log.warning(f"Transient HTTP {r.status_code} from backend (attempt {attempt+1}/{MAX_RETRIES+1}). Retrying in {RETRY_DELAY}s...")
                        time.sleep(RETRY_DELAY)
                        RETRY_DELAY *= 1.5  # gentle backoff
                        continue
                    # All retries exhausted
                    log.error(f"Backend returned HTTP {r.status_code} after {MAX_RETRIES+1} attempts.")
                    return False, last_error

                return False, f"HTTP {r.status_code}: {r.text[:200]}"

            except requests.exceptions.Timeout:
                elapsed = time.time() - start_ts
                log.error(f"AI_PROVIDER_GENERATE_END | ELAPSED: {elapsed:.3f}s | ERROR: Timeout | ATTEMPT: {attempt+1}")
                last_error = "SentinelML AI service did not respond within 90 seconds."
                if attempt < MAX_RETRIES:
                    log.warning(f"Timeout on attempt {attempt+1}. Retrying in {RETRY_DELAY}s...")
                    time.sleep(RETRY_DELAY)
                    RETRY_DELAY *= 1.5
                    continue
                return False, last_error
            except requests.exceptions.ConnectionError:
                return False, "Unable to reach SentinelML AI service."
            except Exception as e:
                return False, str(e)

        return False, last_error or "SentinelML AI service is unavailable."

