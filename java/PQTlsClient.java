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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;

import java.net.Socket;

import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

public class PQTlsClient {
	public static void main(String[] args) throws IOException {
		if ((args.length < 1) || (args.length > 2)) {
				System.err.println("Usage: PQTlsClient <hostname> [<port>]");
				System.exit(1);
		}
		String host = args[0];

		int port = 443;
		if (args.length == 2) {
				try {
						port = Integer.parseInt(args[1]);
						if ((port < 1) || (port > 65535)) {
								throw new IllegalArgumentException("Invalid port number.");
						}
				} catch (Exception e){
						System.err.println("Invalid port number.");
						System.exit(1);
				}

		}
		Socket socket = new Socket(host, port);

		TlsClientProtocol clientProtocol = new TlsClientProtocol(socket.getInputStream(), socket.getOutputStream());

		TlsClient client = new DefaultTlsClient(new BcTlsCrypto()) {
			@Override
			public int[] getSupportedCipherSuites() {
				return new int[] {
					CipherSuite.TLS_AES_128_GCM_SHA256
				};
			}

			@Override
			protected ProtocolVersion[] getSupportedVersions() {
				return ProtocolVersion.TLSv13.downTo(ProtocolVersion.TLSv13);
			}

			@Override
			public Vector<Integer> getEarlyKeyShareGroups() {
				Vector<Integer> earlyGroups = new Vector<>();
				earlyGroups.add(NamedGroup.x25519);
				earlyGroups.add(NamedGroup.X25519MLKEM768);
				return earlyGroups;
			}

			@Override
			public Hashtable getClientExtensions() throws IOException {
				Hashtable extensions = super.getClientExtensions();

				Vector<Integer> namedGroups = new Vector<>();
				namedGroups.add(NamedGroup.x25519);
				namedGroups.add(NamedGroup.X25519MLKEM768);

				TlsExtensionsUtils.addSupportedGroupsExtension(extensions, namedGroups);
				return extensions;
			}

			@Override
			public TlsAuthentication getAuthentication() throws IOException {
				return new TlsAuthentication() {
					@Override
					public void notifyServerCertificate(TlsServerCertificate serverCertificate) {
						// I'm terrible and don't validate the server cert, because
						// I only care about PQC capability.
						return;
					}

					@Override
					public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) {
						// Sorry, no mTLS.
						return null;
					}
				};
			}
		};

		clientProtocol.connect(client);

		OutputStream tlsOut = clientProtocol.getOutputStream();
		BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(tlsOut, "UTF-8"));
		writer.write("GET / HTTP/1.1\r\n");
		writer.write("Host: " + host + "\r\n");
		writer.write("Connection: close\r\n");
		writer.write("\r\n");
		writer.flush();

		// Read HTTP response
		InputStream tlsIn = clientProtocol.getInputStream();
		BufferedReader reader = new BufferedReader(new InputStreamReader(tlsIn, "UTF-8"));
		String line;
		while ((line = reader.readLine()) != null) {
			System.out.println(line);
		}

		socket.close();
	}
}
