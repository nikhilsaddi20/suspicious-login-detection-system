import java.io.IOException;
import java.util.Scanner;

/**
 * Main entry point and text-based UI for the Suspicious Login Detection System.
 * Provides menu options to exercise all features and to save/load data.
 */
public class Main {
    private static final String DEFAULT_SAVE = "sld_system_data.txt";

    public static void main(String[] args) {
        SecuritySystem system = new SecuritySystem();
        Scanner scanner = new Scanner(System.in);

        // Try to load default file 
        try {
            system.loadFromFile(DEFAULT_SAVE);
            System.out.println("Loaded saved data from " + DEFAULT_SAVE);
        } catch (IOException ignored) {
            // No saved data found; continue fresh
        }

        while (true) {
            System.out.println("\n===== SUSPICIOUS LOGIN DETECTION SYSTEM =====");
            System.out.println(system.status());
            System.out.println("1. Add Login Attempt");
            System.out.println("2. Display All Logs");
            System.out.println("3. Sort Logs (by Username)");
            System.out.println("4. View Pending Alerts");
            System.out.println("5. Dismiss Next Alert");
            System.out.println("6. Undo Alert Dismissal");
            System.out.println("7. Save Data");
            System.out.println("8. Load Data");
            System.out.println("9. Exit");
            System.out.print("Select option: ");

            String input = scanner.nextLine();
            if (!input.matches("\\d+")) {
                System.out.println("Invalid input. Enter a number.");
                continue;
            }

            int choice = Integer.parseInt(input);

            switch (choice) {
                case 1:
                    System.out.print("Enter username: ");
                    String user = scanner.nextLine().trim();

                    System.out.print("Enter IP address: ");
                    String ip = scanner.nextLine().trim();

                    System.out.print("Timestamp (e.g., 2025-11-23 14:00): ");
                    String time = scanner.nextLine().trim();

                    System.out.print("Success? (true/false): ");
                    String s = scanner.nextLine().trim();
                    boolean success = Boolean.parseBoolean(s);

                    system.addLoginAttempt(user, ip, time, success);
                    break;

                case 2:
                    system.displayLogs();
                    break;

                case 3:
                    system.sortLogs();
                    break;

                case 4:
                    system.viewAlerts();
                    break;

                case 5:
                    system.dismissAlert();
                    break;

                case 6:
                    system.undoDismiss();
                    break;

                case 7:
                    System.out.print("Save filename (blank for default '" + DEFAULT_SAVE + "'): ");
                    String outFile = scanner.nextLine().trim();
                    if (outFile.isEmpty()) outFile = DEFAULT_SAVE;
                    try {
                        system.saveToFile(outFile);
                        System.out.println("Saved to " + outFile);
                    } catch (IOException e) {
                        System.out.println("Error saving file: " + e.getMessage());
                    }
                    break;

                case 8:
                    System.out.print("Load filename (blank for default '" + DEFAULT_SAVE + "'): ");
                    String inFile = scanner.nextLine().trim();
                    if (inFile.isEmpty()) inFile = DEFAULT_SAVE;
                    try {
                        system.loadFromFile(inFile);
                        System.out.println("Loaded from " + inFile);
                    } catch (IOException e) {
                        System.out.println("Error loading file: " + e.getMessage());
                    }
                    break;

                case 9:
                    // Auto-save on exit (best-effort)
                    try {
                        system.saveToFile(DEFAULT_SAVE);
                        System.out.println("Auto-saved to " + DEFAULT_SAVE);
                    } catch (IOException ignored) { }
                    System.out.println("Exiting system...");
                    scanner.close();
                    return;

                default:
                    System.out.println("Invalid option.");
            }
        }
    }
}
