package kylookhttp;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.jayway.jsonpath.JsonPath;

import java.io.IOException;
import java.security.cert.CertificateException;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

//import javax.crypto.Cipher;

/*
 * 
CREATE TABLE Persons (
    PersonID int,
    LastName varchar(255),
    FirstName varchar(255),
    Address varchar(255),
    City varchar(255)
); 
 */
/* This example shows how to use the CipherTrust Manager encrypt/decrypt REST API.  
 * It uses a simple AWS RDS Mysql table listed above to insert data.
 * The city field holds the type of test or the tag value if using a mode of gcm 
 */
public class AWSMysqlRDSCTMRestApi {
	String token = null;
	String key = null;
	String ctmip = "192.168.1.25";
	// public static final String CTMIP = "192.168.1.25";
	public static final String endbracket = "}";
	public static final String quote = "\"";
	public static final String comma = ",";

	public static final String plaintexttag = "{\"plaintext\":";
	public static final String tag = "kBr5A0fbPjPg7lS1bB6wfw==";
	public static final String iv = "VCC3VwxWu6Z6jfQw";
	public static final String mode = "gcm";
	public static final String aadtag = "\"aad\":";
	public static final String idtag = "\"id\":";
	public static final String typetag = "\"type\":";
	public static final String type = "name";
	public static final String aad = "YXV0aGVudGljYXRl";
	public static final String ciphertexttag = "{\"ciphertext\":";
	public static final String tagtag = "\"tag\":";
	public static final String ivtag = "\"iv\":";
	public static final String modetag = "\"mode\":";

	public static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
	public static final MediaType JSONTXT = MediaType.get("text/plain");
	OkHttpClient client = getUnsafeOkHttpClient();

	String postfpe(String url, String text) throws IOException {
		RequestBody body = RequestBody.create(JSONTXT, text);
		Request request = new Request.Builder().url(url).post(body).addHeader("Authorization", "Bearer " + this.token)
				.addHeader("Accept", "text/plain").addHeader("Content-Type", "text/plain").build();
		try (Response response = client.newCall(request).execute()) {
			return response.body().string();
		}
	}

	String post(String url, String json) throws IOException {
		RequestBody body = RequestBody.create(json, JSON);
		Request request = new Request.Builder().url(url).post(body).addHeader("Authorization", "Bearer " + this.token)
				.addHeader("Accept", "application/json").addHeader("Content-Type", "application/json").build();
		try (Response response = client.newCall(request).execute()) {
			return response.body().string();
		}
	}

	private static String getToken(String ctmip, String username, String password) throws IOException {

		OkHttpClient client = getUnsafeOkHttpClient();
		MediaType mediaType = MediaType.parse("application/json");

		String grant_typetag = "{\"grant_type\":";
		String grant_type = "password";
		String passwordtag = "\"password\":";
		String usernametag = "\"username\":";
		String labels = "\"labels\": [\"myapp\",\"cli\"]}";

		String authcall = grant_typetag + quote + grant_type + quote + comma + usernametag + quote + username + quote
				+ comma + passwordtag + quote + password + quote + comma + labels;

		RequestBody body = RequestBody.create(mediaType, authcall);
		Request request = new Request.Builder().url("https://" + ctmip + "/api/v1/auth/tokens").method("POST", body)
				.addHeader("Content-Type", "application/json").build();

		Response response = client.newCall(request).execute();
		String returnvalue = response.body().string();
		System.out.println("response " + returnvalue);
		String jwt = JsonPath.read(returnvalue.toString(), "$.jwt").toString();
		String refreshtoken = JsonPath.read(returnvalue.toString(), "$.refresh_token").toString();
		System.out.println("jwt = " + jwt);
		System.out.println("refresh = " + refreshtoken);
		return jwt;

	}

	private static OkHttpClient getUnsafeOkHttpClient() {
		try {
			// Create a trust manager that does not validate certificate chains
			final TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
				@Override
				public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType)
						throws CertificateException {
				}

				@Override
				public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType)
						throws CertificateException {
				}

				@Override
				public java.security.cert.X509Certificate[] getAcceptedIssuers() {
					return new java.security.cert.X509Certificate[] {};
				}
			} };

			// Install the all-trusting trust manager
			final SSLContext sslContext = SSLContext.getInstance("SSL");
			sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
			// Create an ssl socket factory with our all-trusting manager
			final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

			OkHttpClient.Builder builder = new OkHttpClient.Builder();
			builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0]);
			builder.hostnameVerifier(new HostnameVerifier() {
				@Override
				public boolean verify(String hostname, SSLSession session) {
					return true;
				}
			});

			OkHttpClient okHttpClient = builder.build();
			return okHttpClient;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static void main(String[] args) throws Exception {

		if (args.length != 8) {
			System.err
					.println("Usage: java AWSMysqlRDSCTMRestApi userid password keyname numberofrecords batchsize mode operation ctmip  " );
			System.exit(-1);
		}

		String username = args[0];
		String password = args[1];
		String keyName = args[2];
		int numberofrecords = Integer.parseInt(args[3]);
		int batchsize = Integer.parseInt(args[4]);
		String mode = args[5];
		String operation = args[6];
		String ctmip = args[7];

		AWSMysqlRDSCTMRestApi awsresrest = new AWSMysqlRDSCTMRestApi();
		awsresrest.key = keyName;
		awsresrest.ctmip = ctmip;
		awsresrest.token = awsresrest.getToken(ctmip, username, password);

		Calendar calendar = Calendar.getInstance();

		// Get start time (this needs to be a global variable).
		Date startDate = calendar.getTime();

		Connection connection = ConnectionObject.getConnection();

		if (mode.equalsIgnoreCase("fpe")) {
			if (operation.equalsIgnoreCase("both")) {
				fpeencrypt(awsresrest, connection, mode, numberofrecords, batchsize);
				fpedecryptdata(awsresrest, connection, mode);
			} else
				fpeencrypt(awsresrest, connection, mode, numberofrecords, batchsize);
		} else {
			if (operation.equalsIgnoreCase("both")) {
				enrypt(awsresrest, connection, mode, numberofrecords, batchsize);
				decryptdata(awsresrest, connection, mode);
			} else
				enrypt(awsresrest, connection, mode, numberofrecords, batchsize);
		}

		if (connection != null)
			connection.close();

		Calendar calendar2 = Calendar.getInstance();

		// Get start time (this needs to be a global variable).
		Date endDate = calendar2.getTime();
		long sumDate = endDate.getTime() - startDate.getTime();
		System.out.println("Total time " + sumDate);
	}

	static void fpedecryptdata(AWSMysqlRDSCTMRestApi awsresrest, Connection connection, String action)
			throws Exception {

		Statement stmt = null;
		try {
			stmt = connection.createStatement();
			String results;

			String sql = "SELECT PersonID, LastName, FirstName, Address, City FROM Persons";
			ResultSet rs = stmt.executeQuery(sql);
			String firstpart = "--data-binary '";
			String thirdpart = "' --compressed";

			while (rs.next()) {
				// Retrieve by column name

				int id = rs.getInt("PersonID");
				String last = rs.getString("LastName");
				String first = rs.getString("FirstName");
				String addr = rs.getString("Address");
				String city = rs.getString("City");
				System.out.print(", last: " + last);
				// System.out.println("data: " + results);
				System.out.print("ID: " + id);
				String[] parts = last.split(" ");
				String sensitive = parts[1];
				sensitive = sensitive.replaceAll("\'", "");
				String text = firstpart + sensitive + thirdpart;
				results = awsresrest.postfpe("https://" + awsresrest.ctmip + "/api/v1/crypto/unhide2?keyName="
						+ awsresrest.key + "&hint=digit", text);

				parts = results.split(" ");
				sensitive = parts[1];
				sensitive = sensitive.replaceAll("\'", "");
				System.out.println("Original Data " + sensitive);
				System.out.print(", First: " + first);
				System.out.println(", addr: " + addr);
			}
			rs.close();

		} catch (SQLException se) {
			// Handle errors for JDBC
			se.printStackTrace();
		} catch (Exception e) {
			// Handle errors for Class.forName
			e.printStackTrace();
		} finally {
			// finally block used to close resources
			try {
				if (stmt != null)
					connection.close();
			} catch (SQLException se) {
			} // do nothing
			try {
				if (connection != null)
					connection.close();
			} catch (SQLException se) {
				se.printStackTrace();
			} // end finally try
		} // end try
		System.out.println("Goodbye!");

	}

	static void decryptdata(AWSMysqlRDSCTMRestApi awsresrest, Connection connection, String action) throws Exception {

		Statement stmt = null;
		try {
			stmt = connection.createStatement();
			String results;

			String sql = "SELECT PersonID, LastName, FirstName, Address, City FROM Persons";
			ResultSet rs = stmt.executeQuery(sql);

			//String key = "1498bd7dab2045a0ad245aa2c37c913106472a736d994d3992e0f1306bbee229";

			while (rs.next()) {
				// Retrieve by column name

				int id = rs.getInt("PersonID");
				String last = rs.getString("LastName");
				String first = rs.getString("FirstName");
				String addr = rs.getString("Address");
				System.out.print(", last: " + last);
				String tag = rs.getString("City");

				String decryptjson = ciphertexttag + quote + last + quote + comma + tagtag + quote + tag + quote 
						+ comma+ modetag + quote + mode + quote + comma 
						+ typetag + quote + type + quote + comma +
						idtag + quote + awsresrest.key + quote + comma + ivtag + quote
						+ iv + quote + comma + aadtag + quote + aad + quote + endbracket;
				results = awsresrest.post("https://" + awsresrest.ctmip + "/api/v1/crypto/decrypt", decryptjson);
				//System.out.println("value " + results);

				String plaintextbase64 = JsonPath.read(results.toString(), "$.plaintext").toString();

				byte[] decryoriginaldata = Base64.getDecoder().decode(plaintextbase64);
				results = new String(decryoriginaldata);
				System.out.println("data: " + results);
				System.out.print(", First: " + first);
				System.out.println(", addr: " + addr);
			}
			rs.close();

		} catch (SQLException se) {
			// Handle errors for JDBC
			se.printStackTrace();
		} catch (Exception e) {
			// Handle errors for Class.forName
			e.printStackTrace();
		} finally {
			// finally block used to close resources
			try {
				if (stmt != null)
					connection.close();
			} catch (SQLException se) {
			} // do nothing
			try {
				if (connection != null)
					connection.close();
			} catch (SQLException se) {
				se.printStackTrace();
			} // end finally try
		} // end try
		System.out.println("Goodbye!");

	}


	static void fpeencrypt(AWSMysqlRDSCTMRestApi awsresrest, Connection connection, String action, int nbrofrecords,
			int batchqty) throws Exception {

		String SQL = "insert into Persons values (?,?,?,?,?)";

		int batchSize = batchqty;
		// int batchSize = 50;
		int count = 0;
		int[] result;
		int size = nbrofrecords;
		connection.setAutoCommit(false);
		PreparedStatement pstmt = connection.prepareStatement(SQL);
		String results = null;
		String sensitive = null;

		for (int i = 1; i <= size; i++) {

			sensitive = randomNumeric(15);

			String firstpart = "--data-binary '";
			String thirdpart = "' --compressed";
			String text = firstpart + sensitive + thirdpart;
			results = awsresrest.postfpe(
					"https://" + awsresrest.ctmip + "/api/v1/crypto/hide2?keyName=" + awsresrest.key + "&hint=digit",
					text);

			//System.out.println("value " + results);
			String ciphertext = JsonPath.read(results.toString(), "$.data").toString();

			pstmt.setInt(1, i);
			pstmt.setString(2, ciphertext);
			pstmt.setString(3, "FirstName");
			pstmt.setString(4, sensitive + " Addr");
			pstmt.setString(5, action);
			pstmt.addBatch();

			count++;

			if (count % batchSize == 0) {
				System.out.println("Commit the batch");
				result = pstmt.executeBatch();
				System.out.println("Number of rows inserted: " + result.length);
				connection.commit();
			}
		}

		if (pstmt != null)
			pstmt.close();
		// if(connection!=null)
		// connection.close();

	}

	static void enrypt(AWSMysqlRDSCTMRestApi awsresrest, Connection connection, String action, int nbrofrecords,
			int batchqty) throws Exception {

		String SQL = "insert into Persons values (?,?,?,?,?)";
		int batchSize = batchqty;
		int count = 0;
		int[] result;
		int size = nbrofrecords;
		connection.setAutoCommit(false);
		PreparedStatement pstmt = connection.prepareStatement(SQL);
		String results = null;
		String sensitive = null;

		String plaintextbase64 = null;

		for (int i = 1; i <= size; i++) {

			sensitive = randomNumeric(15);
			byte[] dataBytes = sensitive.getBytes();
			plaintextbase64 = Base64.getEncoder().encodeToString(dataBytes);

			String encryptjson = plaintexttag + quote + plaintextbase64 + quote + comma + tagtag + quote + tag + quote
					+ comma + modetag + quote + mode + quote + comma + idtag + quote + awsresrest.key + quote + comma
					+ ivtag + quote + iv + quote + comma + aadtag + quote + aad + quote + endbracket;
			//System.out.println("encryptjson json " + encryptjson);

			results = awsresrest.post("https://" + awsresrest.ctmip + "/api/v1/crypto/encrypt", encryptjson);

			//System.out.println("value " + results);
			String ciphertext = JsonPath.read(results.toString(), "$.ciphertext").toString();
			String tagtext = JsonPath.read(results.toString(), "$.tag").toString();
			pstmt.setInt(1, i);
			pstmt.setString(2, ciphertext);
			pstmt.setString(3, "FirstName");
			pstmt.setString(4, sensitive + " Addr");
			pstmt.setString(5, tagtext);
			pstmt.addBatch();

			count++;

			if (count % batchSize == 0) {
				System.out.println("Commit the batch");
				result = pstmt.executeBatch();
				System.out.println("Number of rows inserted: " + result.length);
				connection.commit();
			}
		}

		if (pstmt != null)
			pstmt.close();
		// if(connection!=null)
		// connection.close();

	}

	// private static final String ALPHA_NUMERIC_STRING =
	// "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	public static String randomAlphaNumeric(int count) {
		StringBuilder builder = new StringBuilder();
		while (count-- != 0) {
			int character = (int) (Math.random() * ALPHA_NUMERIC_STRING.length());
			builder.append(ALPHA_NUMERIC_STRING.charAt(character));
		}
		return builder.toString();
	}

	private static final String NUMERIC_STRING = "0123456789";

	public static String randomNumeric(int count) {
		StringBuilder builder = new StringBuilder();
		while (count-- != 0) {
			int character = (int) (Math.random() * NUMERIC_STRING.length());
			builder.append(NUMERIC_STRING.charAt(character));
		}
		return builder.toString();
	}

}
