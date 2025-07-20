// vim: ts=4 sw=4:
//
// A simple PQC-enabled HTTPS client PoC.
//
// Jan Schaumann <jschauma@netmeister.org>
//
// This code is in the public domain.
//
// See this link for more information:
// https://www.netmeister.org/blog/pqc-pocs.html
//
// See also:
// https://github.com/bcgit/bc-java/issues/2117

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.*;
import org.bouncycastle.tls.crypto.impl.bc.*;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.logging.*;
import java.util.Date;

public class PQTlsServer {

	private static final String PROGNAME = "PqcTlsServer";
	private static int VERBOSITY = 0;

	private static String CERT = "cert.pem";
	private static String KEY = "key.pem";
	private static String LOG = "pqcpoc.log";
	private static int PORT = 443;
	private static boolean pqcOnly = false;

	private static final Logger LOGGER = Logger.getLogger(PROGNAME);

	private static final String HEAD = """
<!DOCTYPE html>

<html lang="en">
  <head>
    <title>PQC PoC</title>
    <meta http-equiv="content-type" content= "text/html; charset=utf-8">
    <link rel="icon" href="data:,">
  </head>

  <body>
    <h1>PQC PoC</h1>
    <hr class="noshade" style="width:100%;">
    <p>
      This site uses: BouncyCastle 1.81
    </p>
    <p>
      (See also: <code>host -t txt java-bc.pqc.dotwtf.wtf</code>)
    </p>
    <hr class="noshade" style="width:100%;">
    <p>
      You appear to be using:
    </p>
    <p>
""";

	private static final String TAIL = """
    </p>
    <hr class="noshade" style="width:100%;">
    <p>
      Also available:
      <ul>
        <li><a href="https://golang.pqc.dotwtf.wtf">https://golang.pqc.dotwtf.wtf</a></li>
        <li><a href="https://openssl-nginx.pqc.dotwtf.wtf">https://openssl-nginx.pqc.dotwtf.wtf</a></li>
        <li><a href="https://openssl-oqs-apache.pqc.dotwtf.wtf">https://openssl-oqs-apache.pqc.dotwtf.wtf</a></li>
        <li><a href="https://boringssl-nginx.pqc.dotwtf.wtf">https://boringssl-nginx.pqc.dotwtf.wtf</a></li>
      </ul>
    </p>
    <hr class="noshade" style="width:100%;">
    <small>
    [<a href="https://www.netmeister.org/">homepage</a>]&nbsp;
    [<a href="mailto:jschauma@netmeister.org">jschauma@netmeister.org</a>]&nbsp;
    [<a href="https://mstdn.social/@jschauma/">@jschauma</a>]&nbsp;
    </small>
    <hr class="noshade" style="width:100%;">
  </body>
</html>
""";

	private static void usage() {
		System.out.printf("Usage: %s [-hvo] [-c cert] [-k key] [-l file] [-p port]\n", PROGNAME);
		System.out.printf("        -c cert  x509 cert to use (PEM format)\n");
		System.out.printf("        -h       print this help and exit\n");
		System.out.printf("        -k key   x509 key to use (PEM format)\n");
		System.out.printf("        -l file  log requests to this file\n");
		System.out.printf("        -o       only offer X25519MLKEM\n");
		System.out.printf("        -p port  listen on this port (default: %d)\n", PORT);
		System.out.printf("        -v       increase verbosity\n");
	}

	private static void argcheck(String flag, String[] args, int i) {
		if (args.length <= (i + 1)) {
			System.err.printf("'%s' needs an argument\n", flag);
			System.exit(1);
			/* NOTREACHED */
		}
	}

	private static void getopt(String[] args) {
		boolean eatit = false;
		boolean expectArgs = true;
		for (int i = 0; i < args.length; i++) {
			if (eatit) {
				eatit = false;
				continue;
			}
			if (!expectArgs) {
				System.err.println("Unexpected arguments after processing command-line flags.");
				System.exit(1);
				/* NOTREACHED */
			}
			switch (args[i]) {
				case "-c":
					eatit = true;
					argcheck("-c", args, i);
					CERT = args[i+1];
					break;
				case "-h":
					usage();
					System.exit(0);
					/* NOTREACHED */
					break;
				case "-k":
					eatit = true;
					argcheck("-k", args, i);
					KEY = args[i+1];
					break;
				case "-l":
					eatit = true;
					argcheck("-l", args, i);
					LOG = args[i+1];
					break;
				case "-o":
					pqcOnly = true;
					break;
				case "-p":
					eatit = true;
					argcheck("-p", args, i);
					try {
						PORT = Integer.parseInt(args[i+1]);
					} catch (NumberFormatException e) {
						System.err.printf("Invalid number '%s'.\n", args[i+1]);
						System.exit(1);
						/* NOTREACHED */
					}
					if ((PORT < 1) || (PORT > 65535)) {
						System.err.printf("Invalid port '%s'.\n", args[i+1]);
						System.exit(1);
						/* NOTREACHED */
					}
					break;
				case "-v":
					VERBOSITY++;
					break;
				default:
					System.err.printf(args[i]);
					usage();
					System.exit(1);
					/* NOTREACHED */
					break;
			}
		}
	}

	private static void redirectHttp() throws IOException {
		HttpServer httpServer = HttpServer.create(new InetSocketAddress(80), 0);
		httpServer.createContext("/", new HttpHandler() {
			@Override
			public void handle(HttpExchange exchange) throws IOException {
				String host = exchange.getRequestHeaders().getFirst("Host");
				if (host == null) {
					host = "localhost";
				}

				String requestURI = exchange.getRequestURI().toString();
				String redirectUrl = "https://" + host + requestURI;

				exchange.getResponseHeaders().add("Location", redirectUrl);
				exchange.sendResponseHeaders(301, -1);
			}
		});
		httpServer.setExecutor(null);
		httpServer.start();
	}

	private static void verbose(String out, int... l) {
		int level = 1;
		if (l.length > 0) {
			level = l[0];
		}
		if (level <= VERBOSITY) {
			for (int i = 0; i < level; i++) {
				System.err.print("=");
			}
			System.err.println("> " + out);
		}
	}

	public static void main(String[] args) throws Exception {
		getopt(args);

		redirectHttp();

		try {
			LogManager.getLogManager().reset();
			FileHandler fileHandler = new FileHandler(LOG, true);
			fileHandler.setFormatter(new Formatter() {
				private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

				@Override
				public String format(LogRecord record) {
					String timestamp = dateFormat.format(new Date(record.getMillis()));
					return timestamp + " " + record.getMessage() + System.lineSeparator();
				}
			});

            LOGGER.addHandler(fileHandler);

		} catch (IOException e) {
            e.printStackTrace();
		}

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		ServerSocket serverSocket = new ServerSocket(PORT);
		verbose("TLS 1.3 Server running on port " + PORT);

		while (true) {
			Socket socket = serverSocket.accept();
			String clientIP = socket.getInetAddress().getHostAddress();

			verbose("Client connected: " + clientIP, 2);

			new Thread(() -> { try {
					TlsServerProtocol tlsServerProtocol = new TlsServerProtocol(socket.getInputStream(), socket.getOutputStream());
					Tls13Server server = new Tls13Server();
					tlsServerProtocol.accept(server);

					BufferedReader reader = new BufferedReader(new InputStreamReader(tlsServerProtocol.getInputStream()));
					BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(tlsServerProtocol.getOutputStream()));

					handleRequest(server, reader, writer, clientIP);
					tlsServerProtocol.close();
					socket.close();
				} catch (Exception e) {
					// e.g., client doesn't speak PQC; nothing to do
					// e.printStackTrace();
				}
			}).start();
		}
	}

	private static void sendReply(String e, BufferedWriter w) throws Exception {
			w.write(e + "\r\n");
			w.write("Server: BouncyCastle 1.81\r\n");
			w.write("Connection: close\r\n");
			w.write("\r\n");
			w.flush();
	}

	private static void handleRequest(Tls13Server s, BufferedReader r, BufferedWriter w, String ip) throws Exception {

		String req = r.readLine();
		if (req == null || req.isEmpty()) {
			return;
		}
		verbose("HTTP Request: " + req, 2);

		LOGGER.info(ip + " " + req);

		String[] parts = req.split(" ");
		if (parts.length != 3) {
			sendReply("HTTP/1.1 400 Bad Request", w);
			return;
		}

		String method = parts[0];
		String uri = parts[1];
		String version = parts[2];

		if (! (method.equals("GET") || method.equals("HEAD"))) {
        	sendReply("HTTP/1.1 501 Not Implemented", w);
			return;
		}

		if (!uri.equals("/")) {
        	sendReply("HTTP/1.1 404 Not Found", w);
			return;
		}

		if (!(version.equals("HTTP/1.1") || version.equals("HTTP/1.0"))) {
			sendReply("HTTP/1.1 505 Version Not Supported", w);
			return;
		}

		String line;
		while ((line = r.readLine()) != null && !line.isEmpty()) {
			verbose("Header: " + line, 3);
		}

		if (method.equals("HEAD")) {
			sendReply("HTTP/1.1 200 Ok", w);
			return;
		}

		String body = HEAD;
		body += "      Protocol: " + s.context.getClientVersion().getName() + "<br>\n";
		body += "      Cipher: " + s.getNegotiatedCipherSuiteName() + "<br>\n";
		if (pqcOnly) {
			body += "      Group: X25519MLKEM768<br>\n"; // it's the only one we support
			body += "      TLS HRR: false<br>\n"; // we only support one group
		}

		body += TAIL;

		w.write("HTTP/1.1 200 OK\r\n");
		w.write("Content-Type: text/html\r\n");
		w.write("Content-Length: " + body.length() + "\r\n");
		w.write("Server: BouncyCastle 1.81\r\n");
		w.write("Connection: close\r\n");
		w.write("\r\n");
		w.write(body);
		w.flush();
	}

	static class Tls13Server extends DefaultTlsServer {
		private final BcTlsCrypto crypto;
		private TlsServerContext context;

		public Tls13Server() {
			super(new BcTlsCrypto(new SecureRandom()));
			this.crypto = (BcTlsCrypto) getCrypto();
		}

		@Override
		public void init(TlsServerContext context) {
			super.init(context);
			this.context = context;
		}

		@Override
		protected ProtocolVersion[] getSupportedVersions() {
			return ProtocolVersion.TLSv13.only();
		}

		@Override
		public TlsCredentials getCredentials() throws IOException {
			return loadSignerCredentials(CERT, KEY, context);
		}

		@Override
		public int[] getCipherSuites() {
			return new int[] {
				CipherSuite.TLS_AES_128_GCM_SHA256,
				CipherSuite.TLS_AES_256_GCM_SHA384,
				CipherSuite.TLS_CHACHA20_POLY1305_SHA256
			};
		}

		@Override
		public int[] getSupportedGroups() {
			if (pqcOnly) {
				return new int[] {
					NamedGroup.X25519MLKEM768
				};
			}

			return new int[] {
				NamedGroup.x25519,
				NamedGroup.X25519MLKEM768
			};
		}

		public static String getCipherSuiteName(int id) {
			switch (id) {
				case 4865: return "TLS_AES_128_GCM_SHA256";
				case 4866: return "TLS_AES_256_GCM_SHA384";
				case 4867: return "TLS_CHACHA20_POLY1305_SHA256";
				default: return "Unknown (ID: " + id + ")";
			}
		}

		public String getNegotiatedCipherSuiteName() {
			SecurityParameters params = context.getSecurityParameters();
			if (params == null) return "Unknown";
			return getCipherSuiteName(params.getCipherSuite());
		}

		private TlsCredentialedSigner loadSignerCredentials(String certFile, String keyFile, TlsServerContext context) throws IOException {
			// Load cert
			X509CertificateHolder certHolder;
			try (PEMParser certParser = new PEMParser(new FileReader(certFile))) {
				Object obj = certParser.readObject();
				if (!(obj instanceof X509CertificateHolder)) {
					throw new IOException("Expected X509CertificateHolder but got " + obj);
				}
				certHolder = (X509CertificateHolder) obj;
			}

			// Load private key
			PrivateKeyInfo keyInfo;
			try (PEMParser keyParser = new PEMParser(new FileReader(keyFile))) {
				Object obj = keyParser.readObject();
				if (!(obj instanceof PrivateKeyInfo)) {
					throw new IOException("Expected PrivateKeyInfo but got " + obj);
				}
				keyInfo = (PrivateKeyInfo) obj;
			}

			AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(keyInfo);
			TlsCertificate tlsCert = new BcTlsCertificate(crypto, certHolder.getEncoded());

			CertificateEntry[] entries = new CertificateEntry[] { new CertificateEntry(tlsCert, null) };
			Certificate certificate = new Certificate(new byte[0], entries);
			int sigScheme = SignatureScheme.rsa_pss_rsae_sha256;
			short hash = (short)((sigScheme >> 8) & 0xFF);
			short signature = (short)(sigScheme & 0xFF);

			SignatureAndHashAlgorithm sigAndHash = new SignatureAndHashAlgorithm(hash, signature);
			return new BcDefaultTlsCredentialedSigner(
				new TlsCryptoParameters(context),
				crypto,
				privateKey,
				certificate,
				sigAndHash
			);
		}
	}
}
