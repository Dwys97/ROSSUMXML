import http.server
import socketserver
import requests
import os

PORT = 8080
BACKEND_URL = 'http://localhost:3000'
DIRECTORY = 'frontend'

class ProxyHandler(http.server.SimpleHTTPRequestHandler):
    # --- START: Add this section to fix MIME types ---
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    # Add .jsx to the list of known script types
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        '.jsx': 'text/javascript',
    }
    # --- END: Add this section ---


    def do_POST(self):
        if self.path.startswith('/api'):
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            try:
                # Forward the request to the backend
                backend_response = requests.post(
                    f"{BACKEND_URL}{self.path}",
                    headers={ 'Content-Type': 'application/json' },
                    data=post_data,
                    timeout=30
                )

                # Send backend response back to the client
                self.send_response(backend_response.status_code)
                for key, value in backend_response.headers.items():
                    if key.lower() not in ['content-encoding', 'transfer-encoding', 'connection']:
                         self.send_header(key, value)
                self.end_headers()
                self.wfile.write(backend_response.content)

            except requests.exceptions.RequestException as e:
                self.send_error(500, f"Proxy error: {e}")

        else:
            # If not an API call, fallback to serving static files
            super().do_GET()


with socketserver.TCPServer(("", PORT), ProxyHandler) as httpd:
    print(f"Serving at port {PORT}, proxying /api to {BACKEND_URL}")
    httpd.serve_forever()