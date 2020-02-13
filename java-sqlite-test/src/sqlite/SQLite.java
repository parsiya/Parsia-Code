package sqlite;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.commons.io.IOUtils;

/**
 * SQLite
 */
public class SQLite {

    private static final String databasefile = "test.sqlite";
    private static final String createTableQuery =
        "CREATE TABLE IF NOT EXISTS ESLINT (" +
        "URL TEXT NOT NULL, " +
        "REFERER TEXT NOT NULL, " + 
        "HASH TEXT NOT NULL, " +
        "BEAUTIFIED TEXT, "+ 
        "STATUS TEXT, " +
        "ESLINT TEXT, " +
        "PROCESSED INTEGER, " +
        "NUM_RESULTS INTEGER, " +
        "PRIMARY KEY (URL, REFERER, HASH) " +
        ") WITHOUT ROWID";

    private static final String addRowQuery =
        "INSERT INTO ESLINT " +
        "(URL, REFERER, HASH, BEAUTIFIED, STATUS, ESLINT, PROCESSED, NUM_RESULTS) " +
        "VALUES (?,?,?,?,?,?,?,?)";

    private static final String updateHashTrigger = 
        "CREATE TRIGGER update_for_all_hashes\n" +
        "AFTER UPDATE OF PROCESSED ON ESLINT\n" +
        "WHEN\n" +
        "    NEW.PROCESSED == 1\n" +
        "BEGIN\n" +
        "    UPDATE ESLINT\n" +
        "    SET BEAUTIFIED = new.BEAUTIFIED,\n" +
        "        STATUS = new.STATUS,\n" +
        "        PROCESSED = new.PROCESSED,\n" +
        "        NUM_RESULTS = new.NUM_RESULTS\n" +
        "    WHERE\n" +
        "        HASH == new.HASH;\n" +
        "END";

    public static void main(String[] args) {

        Connection connection;
        try {
            // Creates the database if it does not exist.
            connection = DriverManager.getConnection("jdbc:sqlite:" + databasefile);
            DatabaseMetaData dbMetadata = connection.getMetaData();
            System.out.println(dbMetadata.getDriverName());

            // Create the table if it does not exist.
            Statement createTable = connection.createStatement();
            createTable.execute(createTableQuery);
            System.out.println("Created the table if it was not present in the file");

            System.out.println(updateHashTrigger);

            // Add the trigger to the database.
            createTable.execute(updateHashTrigger);
            System.out.println("Added the trigger.");
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
        
        for (int i = 0; i < 10; i++) {
            // Add some items to the table.
            String counter = Integer.toString(i);

            int count = 0;
			try {
				count = insertRow(
                                  connection,
                                  counter + "https://example.net",
                                  counter + "https://referer.com",
                                //   counter + "hashhash",
                                  "0hashhash",
                                  counter + "JavaScript body",
                                  counter + "Status",
                                  counter + "Eslint results",
                                  i,
                                  i * 10
				);
			} catch (SQLException e) {
                // If INSERT fails because the url-referer-hash combination already
                // exists, then the message will contain "UNIQUE constraint failed".
                if (e.getMessage().contains("UNIQUE constraint failed")) {
                    System.out.println("Row already exists.");
                    continue;
                }
			}

            System.out.printf("Count : %d\n", count);
        }

        // // Add a duplicate row
        // int count = 0;
		// try {
		// 	count = insertRow(
        //                       connection,
        //                       "0https://example.net",
        //                       "0https://referer.com",
        //                       "0hashhash",
        //                       "0JavaScript body",
        //                       "0Status",
        //                       "0Eslint results",
        //                       0,
        //                       0
		// 	);
        // } catch (SQLException e) {
        //     // If INSERT fails because the url-referer-hash combination already
        //     // exists, then the message will contain "UNIQUE constraint failed".
        //     if (e.getMessage().contains("UNIQUE constraint failed")) {
        //         System.out.println("Row already exists.");
        //     }
        //     return;
        // }

        // System.out.printf("Count : %d\n", count);

        // Add a trigger to update the status of all records with the same hash
        // value as the record being updated.

        final String updateStatusQuery =
        "UPDATE ESLINT\n" +
        "SET PROCESSED = ?,\n" +
        "    STATUS = ?,\n" +
        "    BEAUTIFIED = ?,\n" +
        "    NUM_RESULTS = ?\n" +
        "WHERE URL = ? AND REFERER = ? AND HASH = ?";
        // Update a sample row.

        PreparedStatement updateRow;
        try {
            updateRow = connection.prepareStatement(updateStatusQuery);
            updateRow.setInt(1, 1);
            updateRow.setString(2, "New status");
            updateRow.setString(3, "New Beautified");
            updateRow.setInt(4, 100);
            updateRow.setString(5, "0https://example.net");
            updateRow.setString(6, "0https://referer.com");
            updateRow.setString(7, "0hashhash");

            System.out.println(updateStatusQuery);

            int count = updateRow.executeUpdate();
            System.out.printf("Update count: %d\n", count);
        } catch (SQLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }





        // } catch (SQLException e) {
        //     // TODO Auto-generated catch block
        //     // e.printStackTrace();
        //     // System.out.println(e.getMessage());

        //     // If INSERT fails because the url-referer-hash combination already
        //     // exists, then the message will contain "UNIQUE constraint failed".
        //     if (e.getMessage().contains("UNIQUE constraint failed")) {
        //         System.out.println("Row already exists.");
        //     }

        // }

        System.out.println("Done");
    }

    private static int insertRow(
        Connection connection, String url, String referer, String hash,
        String beautified, String status, String eslint,
        int processed, int numResults
    ) throws SQLException {

        PreparedStatement addRow = connection.prepareStatement(addRowQuery);
        addRow.setString(1, url);
        addRow.setString(2, referer);
        addRow.setString(3, hash);
        addRow.setString(4, beautified);
        addRow.setString(5, status);
        addRow.setString(6, eslint);
        addRow.setInt(7, processed);
        addRow.setInt(8, numResults);

        return addRow.executeUpdate();
    }
    

    public static String getResourceFile(Class cls, String name) throws IOException {
        InputStream in = cls.getResourceAsStream(name);
        String content = IOUtils.toString(in, "UTF-8");
        in.close();
        return content;
    }
}