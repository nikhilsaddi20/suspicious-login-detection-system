import java.io.*;
import java.util.*;

/**
 * Core system: stores login attempts, tracks failed counts, manages alerts,
 * supports sorting, saving to file, and loading from file.
 *
 * Data file format (plain text):
 * - Each line begins with a section prefix:
 *   L|username|ip|timestamp|success      -> LoginAttempt
 *   F|ip|count                           -> failedAttempts map
 *   A|ip|message|timestamp               -> alertQueue (FIFO)
 *   D|ip|message|timestamp               -> dismissedAlerts (stack order saved bottom->top)
 */
public class SecuritySystem {

    /** Stores all login attempts */
    private List<LoginAttempt> logs = new ArrayList<>();

    /** Tracks failed login attempts per IP address */
    private Map<String, Integer> failedAttempts = new HashMap<>();

    /** Queue storing alerts waiting for analyst review (FIFO) */
    private Queue<Alert> alertQueue = new LinkedList<>();

    /** Stack storing dismissed alerts for undo functionality (LIFO) */
    private Stack<Alert> dismissedAlerts = new Stack<>();

    /** Threshold for failed login attempts before generating an alert */
    private final int THRESHOLD = 3;

    /**
     * Adds a login attempt, updates failure counters and generates alerts
     * when threshold is hit.
     *
     * @param user    username
     * @param ip      ip address
     * @param time    timestamp
     * @param success whether login succeeded
     */
    public void addLoginAttempt(String user, String ip, String time, boolean success) {
        LoginAttempt attempt = new LoginAttempt(user, ip, time, success);
        logs.add(attempt);

        if (!success) {
            int count = failedAttempts.getOrDefault(ip, 0) + 1;
            failedAttempts.put(ip, count);

            if (count == THRESHOLD) {
                Alert a = new Alert(ip, "Multiple failed login attempts detected.", time);
                alertQueue.add(a);
                System.out.println("** ALERT GENERATED ** Suspicious IP: " + ip);
            }
        }

        System.out.println("Login recorded successfully.");
    }

    /**
     * Print all stored login attempts to standard output.
     */
    public void displayLogs() {
        if (logs.isEmpty()) {
            System.out.println("No login attempts recorded.");
            return;
        }
        for (LoginAttempt log : logs) {
            System.out.println(log);
        }
    }

    /**
     * Sorts the login logs by username using bubble sort (custom algorithm).
     * Uses the Comparable implementation on LoginAttempt.
     */
    public void sortLogs() {
        if (logs.size() < 2) {
            System.out.println("Not enough logs to sort.");
            return;
        }

        // Simple bubble sort (required custom algorithm)
        for (int i = 0; i < logs.size() - 1; i++) {
            for (int j = 0; j < logs.size() - i - 1; j++) {
                if (logs.get(j).compareTo(logs.get(j + 1)) > 0) {
                    LoginAttempt temp = logs.get(j);
                    logs.set(j, logs.get(j + 1));
                    logs.set(j + 1, temp);
                }
            }
        }
        System.out.println("Logs sorted by username.");
    }

    /**
     * Shows pending alerts in FIFO order.
     */
    public void viewAlerts() {
        if (alertQueue.isEmpty()) {
            System.out.println("No pending alerts.");
            return;
        }

        System.out.println("=== Pending Alerts ===");
        for (Alert a : alertQueue) {
            System.out.println(a);
        }
    }

    /**
     * Dismiss the next alert (remove from queue) and push it onto the stack
     * so it can be undone later.
     */
    public void dismissAlert() {
        if (alertQueue.isEmpty()) {
            System.out.println("No alerts to dismiss.");
            return;
        }
        Alert removed = alertQueue.remove();
        dismissedAlerts.push(removed);
        System.out.println("Alert dismissed: " + removed.getIpAddress());
    }

    /**
     * Undo the most recent dismissal (pop from stack and add back to queue).
     */
    public void undoDismiss() {
        if (dismissedAlerts.isEmpty()) {
            System.out.println("No dismissed alerts to restore.");
            return;
        }
        Alert restored = dismissedAlerts.pop();
        alertQueue.add(restored);
        System.out.println("Undo complete. Alert restored: " + restored.getIpAddress());
    }

    /**
     * Save the current system state to a file. The format is documented at
     * the top of this class. Existing file will be overwritten.
     *
     * @param filename path to the output file
     * @throws IOException if writing fails
     */
    public void saveToFile(String filename) throws IOException {
        try (BufferedWriter w = new BufferedWriter(new FileWriter(filename))) {
            // Save logs
            for (LoginAttempt la : logs) {
                // L|username|ip|timestamp|success
                w.write(String.join("|", "L", escape(la.getUsername()), escape(la.getIpAddress()), escape(la.getTimestamp()), String.valueOf(la.wasSuccessful())));
                w.newLine();
            }
            // Save failed attempts
            for (Map.Entry<String, Integer> e : failedAttempts.entrySet()) {
                w.write(String.join("|", "F", escape(e.getKey()), String.valueOf(e.getValue())));
                w.newLine();
            }
            // Save alertQueue (FIFO): write in queue order
            for (Alert a : alertQueue) {
                w.write(String.join("|", "A", escape(a.getIpAddress()), escape(a.getMessage()), escape(a.getTimestamp())));
                w.newLine();
            }
            // Save dismissedAlerts stack bottom->top so we can restore order on load
            for (int i = 0; i < dismissedAlerts.size(); i++) {
                Alert a = dismissedAlerts.get(i); // stack provides random access via get
                w.write(String.join("|", "D", escape(a.getIpAddress()), escape(a.getMessage()), escape(a.getTimestamp())));
                w.newLine();
            }
        }
    }

    /**
     * Load system state from a file saved with saveToFile.
     * Clears current in-memory state and replaces with file contents.
     *
     * @param filename path to input file
     * @throws IOException if reading fails
     */
    public void loadFromFile(String filename) throws IOException {
        List<LoginAttempt> newLogs = new ArrayList<>();
        Map<String, Integer> newFailed = new HashMap<>();
        Queue<Alert> newAlerts = new LinkedList<>();
        Stack<Alert> newDismissed = new Stack<>();

        try (BufferedReader r = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                String[] parts = line.split("\\|", -1);
                if (parts.length == 0) continue;
                String tag = parts[0];
                switch (tag) {
                    case "L":
                        // L|username|ip|timestamp|success
                        if (parts.length >= 5) {
                            String user = unescape(parts[1]);
                            String ip = unescape(parts[2]);
                            String time = unescape(parts[3]);
                            boolean succ = Boolean.parseBoolean(parts[4]);
                            newLogs.add(new LoginAttempt(user, ip, time, succ));
                        }
                        break;
                    case "F":
                        // F|ip|count
                        if (parts.length >= 3) {
                            String ip = unescape(parts[1]);
                            int cnt = Integer.parseInt(parts[2]);
                            newFailed.put(ip, cnt);
                        }
                        break;
                    case "A":
                        // A|ip|message|timestamp
                        if (parts.length >= 4) {
                            String ip = unescape(parts[1]);
                            String msg = unescape(parts[2]);
                            String time = unescape(parts[3]);
                            newAlerts.add(new Alert(ip, msg, time));
                        }
                        break;
                    case "D":
                        // D|ip|message|timestamp
                        if (parts.length >= 4) {
                            String ip = unescape(parts[1]);
                            String msg = unescape(parts[2]);
                            String time = unescape(parts[3]);
                            newDismissed.push(new Alert(ip, msg, time));
                        }
                        break;
                    default:
                        // ignore unknown lines
                        break;
                }
            }
        }

        // Replace runtime state
        this.logs = newLogs;
        this.failedAttempts = newFailed;
        this.alertQueue = newAlerts;
        this.dismissedAlerts = newDismissed;
    }

    /**
     * Escape a string so '|' and line breaks do not break the file format.
     */
    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n").replace("\r", "\\r");
    }

    /**
     * Unescape a string which was escaped by escape().
     */
    private String unescape(String s) {
        if (s == null) return "";
        // Replace escape sequences in the reverse order
        String out = s.replace("\\r", "\r").replace("\\n", "\n");
        // For backslashes and escaped pipes, handle carefully:
        // First replace escaped pipe placeholder then restore backslashes.
        out = out.replace("\\|", "|").replace("\\\\", "\\");
        return out;
    }

    /**
     * Simple helper to check whether there are unsaved logs or alerts.
     *
     * @return true if there is any data present
     */
    public boolean hasData() {
        return !logs.isEmpty() || !failedAttempts.isEmpty() || !alertQueue.isEmpty() || !dismissedAlerts.isEmpty();
    }

    /**
     * Returns a user-friendly status line.
     *
     * @return status string
     */
    public String status() {
        return String.format("Logs=%d | Alerts pending=%d | Dismissed=%d",
                logs.size(), alertQueue.size(), dismissedAlerts.size());
    }
}
