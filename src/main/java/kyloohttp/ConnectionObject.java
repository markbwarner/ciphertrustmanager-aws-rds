package kylookhttp;



import java.sql.Connection;
import java.sql.DriverManager;

public class ConnectionObject {
   private static Connection conn = null;
   
   public static Connection getConnection(){
	    String url = "jdbc:mysql://your-rds-instance/vtsdemo?verifyServerCertificate=false&useSSL=true";
	   try{
		   Class.forName("com.mysql.jdbc.Driver").newInstance();
		   conn = DriverManager.getConnection(url,"vormetric","youpwd");
	   }catch(Exception e){
		   e.printStackTrace();
	   }
	   return conn;
   }
}
