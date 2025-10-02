import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Scanner;

public class AuthenticationSystem {

    // Simulates a database storing usernames and HASHED passwords
    private static final HashMap<String, String> userDatabase = new HashMap<>();

    private static String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes());
            
            // Convert byte array to a hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            // Should never happen in a standard Java environment
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    /**
     * Registers a new user with a hashed password.
     * @param username The username to register.
     * @param password The plain text password.
     * @return True if registration was successful, false if username already exists.
     */
    public static boolean registerUser(String username, String password) {
        if (userDatabase.containsKey(username)) {
            return false; // User already exists
        }
        String hashedPassword = hashPassword(password);
        userDatabase.put(username, hashedPassword);
        return true;
    }

    /**
     * Authenticates a user by checking the username and comparing the hashed 
     * input password with the stored hash.
     * @param username The username for login.
     * @param password The plain text password entered by the user.
     * @return True if authentication is successful, false otherwise.
     */
    public static boolean authenticateUser(String username, String password) {
        if (!userDatabase.containsKey(username)) {
            return false; // User not found
        }
        
        String storedHash = userDatabase.get(username);
        String inputHash = hashPassword(password);
        
        // Use a constant-time comparison for security (not strictly necessary here, but good practice)
        return MessageDigest.isEqual(storedHash.getBytes(), inputHash.getBytes());
    }
    
    // --- Main Application Loop and Interface ---

    public static void main(String[] args) {
        // Pre-register a test user
        registerUser("admin", "secure123");
        registerUser("guest", "pass");

        Scanner scanner = new Scanner(System.in);
        int choice = -1;

        while (choice != 0) {
            System.out.println("\n--- Authentication System ---");
            System.out.println("1. Register New User");
            System.out.println("2. Login");
            System.out.println("0. Exit");
            System.out.print("Enter choice: ");

            if (scanner.hasNextInt()) {
                choice = scanner.nextInt();
                scanner.nextLine(); // Consume newline
            } else {
                System.out.println("Invalid input. Please enter a number.");
                scanner.nextLine(); // Consume invalid line
                continue;
            }

            String username, password;

            switch (choice) {
                case 1:
                    System.out.print("Enter new username: ");
                    username = scanner.nextLine();
                    System.out.print("Enter password: ");
                    password = scanner.nextLine();
                    
                    if (registerUser(username, password)) {
                        System.out.println("✅ Registration successful for user: " + username);
                    } else {
                        System.out.println("❌ Registration failed. User '" + username + "' already exists.");
                    }
                    break;

                case 2:
                    System.out.print("Enter username: ");
                    username = scanner.nextLine();
                    System.out.print("Enter password: ");
                    password = scanner.nextLine();
                    
                    if (authenticateUser(username, password)) {
                        System.out.println("\n--- SUCCESS ---");
                        System.out.println("🎉 Welcome, " + username + "! Authentication successful.");
                        System.out.println("-----------------");
                    } else {
                        System.out.println("❌ Login failed. Invalid username or password.");
                    }
                    break;
                
                case 0:
                    System.out.println("System shutting down. Goodbye!");
                    break;

                default:
                    System.out.println("Invalid choice. Please try again.");
            }
        }
        scanner.close();
    }
}
