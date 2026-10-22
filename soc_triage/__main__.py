import os
from http.server import ThreadingHTTPServer

from .server import SocTriageHandler


def main() -> None:
    host = "127.0.0.1"
    port = int(os.environ.get("SOC_TRIAGE_PORT", "8000"))
    server = ThreadingHTTPServer((host, port), SocTriageHandler)
    print(f"SOC triage MVP running at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SOC triage MVP.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
