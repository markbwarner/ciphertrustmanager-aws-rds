
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;

import com.ingrian.security.nae.FPEParameterAndFormatSpec;
import com.ingrian.security.nae.GCMParameterSpec;
import com.ingrian.security.nae.IngrianProvider;
import com.ingrian.security.nae.NAECipher;
import com.ingrian.security.nae.NAEKey;
import com.ingrian.security.nae.NAESession;
import com.ingrian.security.nae.FPEParameterAndFormatSpec.FPEParameterAndFormatBuilder;

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

public class AWSMysqlRDSProtectAppExample3 {

	public static void main(String[] args) throws Exception {
		// Valid options are encrypt or tokenize

		if (args.length != 7) {
			System.err.println("Usage: java AESGCMEncryptionDecryptionSample user password keyname "
					+ "authTagLength iv aad data");
			System.exit(-1);
		}
		String username = args[0];
		String password = args[1];
		String keyName = args[2];
		int authTagLength = Integer.parseInt(args[3]);
		String iv = args[4];
		String aad = args[5];
		String data = args[6];

		byte[] ivBytes = IngrianProvider.hex2ByteArray(iv);
		byte[] aadBytes = IngrianProvider.hex2ByteArray(aad);
		byte[] dataBytes = data.getBytes();

		String action = "javagcm";
 //String action = "baseline";
		
		Calendar calendar = Calendar.getInstance();

		// Get start time (this needs to be a global variable).
		Date startDate = calendar.getTime();

		Connection connection = ConnectionObject.getConnection();

		/*
		 * if(!args[3].contains("null")) { tweakAlgo = args[3]; }
		 */
		String algorithm = null;
		if (action.equalsIgnoreCase("javafpe")) {
			System.out.println("iv: " + IngrianProvider.byteArray2Hex(ivBytes));
			System.out.println("AAD: " + IngrianProvider.byteArray2Hex(aadBytes));
			NAESession session = null;
			session = NAESession.getSession(username, password.toCharArray(), "hello".toCharArray());
			NAEKey key = NAEKey.getSecretKey(keyName, session);
			String tweakData = null;
			String tweakAlgo = null;
			algorithm = "FPE/FF1/CARD10";
			FPEParameterAndFormatSpec param = new FPEParameterAndFormatBuilder(tweakData).set_tweakAlgorithm(tweakAlgo)
					.build();
			fpeencrypt(connection, action, 1000, 100, key, param);
			//fpedecryptdata( connection,  action,  key,  param);
		} else if (action.equalsIgnoreCase("javagcm")) {
			System.out.println("iv: " + IngrianProvider.byteArray2Hex(ivBytes));
			System.out.println("AAD: " + IngrianProvider.byteArray2Hex(aadBytes));
			NAESession session = null;
			session = NAESession.getSession(username, password.toCharArray(), "hello".toCharArray());
			NAEKey key = NAEKey.getSecretKey(keyName, session);
			// algorithm = "AES/GCM/NoPadding";
			GCMParameterSpec spec = new GCMParameterSpec(authTagLength, ivBytes, aadBytes);
			enrypt(connection, action, 1000, 100, key, spec);
			//enrypt(connection, action, 1000, 100, key, spec);
		} else {

			baseline(connection, action, 1000, 100);
		}

		 

		if (connection != null)
			connection.close();

		Calendar calendar2 = Calendar.getInstance();

		// Get start time (this needs to be a global variable).
		Date endDate = calendar2.getTime();
		long sumDate = endDate.getTime() - startDate.getTime();
		System.out.println("Total time " + sumDate);
	}

	static void fpedecryptdata(Connection connection, String action, NAEKey key, FPEParameterAndFormatSpec param)
			throws Exception {

		Statement stmt = null;
		try {
			stmt = connection.createStatement();
			String results;
			String 	algorithm = "FPE/FF1/CARD10";
			String sql = "SELECT PersonID, LastName, FirstName, Address FROM Persons";
			ResultSet rs = stmt.executeQuery(sql);		 
			Cipher decryptCipher = Cipher.getInstance(algorithm, "IngrianProvider");
			// to decrypt data, initialize cipher to decrypt
			decryptCipher.init(Cipher.DECRYPT_MODE, key, param);


			while (rs.next()) {
				// Retrieve by column name

				int id = rs.getInt("PersonID");
				String last = rs.getString("LastName");
				String first = rs.getString("FirstName");
				String addr = rs.getString("Address");
				System.out.print(", last: " + last);

				byte[] decrypt = decryptCipher.doFinal(last.getBytes());
				results = new String(decrypt);
				
				// System.out.println("data: " + results);
				System.out.print("ID: " + id);

				System.out.print(", last decrypted: " + results);
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
	
	static void decryptdata(Connection connection, String action, NAEKey key, GCMParameterSpec param)
			throws Exception {

		Statement stmt = null;
		try {
			stmt = connection.createStatement();
			String results;

			String sql = "SELECT PersonID, LastName, FirstName, Address FROM Persons";
			ResultSet rs = stmt.executeQuery(sql);
			// STEP 5: Extract data from result set
			// Display values
			Cipher decryptCipher = NAECipher.getNAECipherInstance("AES/GCM/NoPadding", "IngrianProvider");
			// to decrypt data, initialize cipher to decrypt
			decryptCipher.init(Cipher.DECRYPT_MODE, key, param);


			while (rs.next()) {
				// Retrieve by column name

				int id = rs.getInt("PersonID");
				String last = rs.getString("LastName");
				String first = rs.getString("FirstName");
				String addr = rs.getString("Address");
				System.out.print(", last: " + last);
		
				byte[] decrypt = decryptCipher.doFinal(IngrianProvider.hex2ByteArray(last));
				results = new String(decrypt);
				
				// System.out.println("data: " + results);
				System.out.print("ID: " + id);

				System.out.print(", last decrypted: " + results);
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
	/**
	 * @param vcs
	 * @param connection
	 * @param action
	 * @param nbrofrecords
	 * @param batchqty
	 * @throws Exception
	 */

	static void fpeencrypt(Connection connection, String action, int nbrofrecords, int batchqty, NAEKey key,
			FPEParameterAndFormatSpec param) throws Exception {

		String SQL = "insert into Persons values (?,?,?,?,?)";
		int batchSize = batchqty;
		int count = 0;
		int[] result;
		int size = nbrofrecords;
		connection.setAutoCommit(false);
		PreparedStatement pstmt = connection.prepareStatement(SQL);
		String results = null;
		String sensitive = null;

		Cipher encryptCipher = NAECipher.getNAECipherInstance("FPE/FF1/CARD10", "IngrianProvider");
		encryptCipher.init(Cipher.ENCRYPT_MODE, key, param);

		for (int i = 1; i <= size; i++) {

			sensitive = randomNumeric(15);
			
			byte[] outbuf = encryptCipher.doFinal(sensitive.getBytes());

			results = new String(outbuf);
			pstmt.setInt(1, i);
			pstmt.setString(2, results);
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

	static void enrypt(Connection connection, String action, int nbrofrecords, int batchqty, NAEKey key,
			GCMParameterSpec spec) throws Exception {

		String SQL = "insert into Persons values (?,?,?,?,?)";

		int batchSize = batchqty;
		int count = 0;
		int[] result;
		int size = nbrofrecords;
		connection.setAutoCommit(false);
		PreparedStatement pstmt = connection.prepareStatement(SQL);
		String results = null;
		String sensitive = null;

		Cipher encryptCipher = NAECipher.getNAECipherInstance("AES/GCM/NoPadding", "IngrianProvider");
		encryptCipher.init(Cipher.ENCRYPT_MODE, key, spec);

		byte[] encrypt = null;

		for (int i = 1; i <= size; i++) {

			sensitive = randomAlphaNumeric(15);
			byte[] dataBytes = sensitive.getBytes();
			encrypt = encryptCipher.doFinal(dataBytes);
			results = IngrianProvider.byteArray2Hex(encrypt);
			// System.out.println("Encrypt: " + results);

			pstmt.setInt(1, i);
			pstmt.setString(2, results);
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
	static void baseline(Connection connection, String action, int nbrofrecords, int batchqty) throws Exception {

		String SQL = "insert into Persons values (?,?,?,?,?)";

		int batchSize = batchqty;
		int count = 0;
		int[] result;
		int size = nbrofrecords;
		connection.setAutoCommit(false);
		PreparedStatement pstmt = connection.prepareStatement(SQL);
		String results = null;
		String sensitive = null;



		for (int i = 1; i <= size; i++) {

			sensitive = randomAlphaNumeric(15);
			byte[] dataBytes = sensitive.getBytes();

			 results = "baseline";
			pstmt.setInt(1, i);
			pstmt.setString(2, results);
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
