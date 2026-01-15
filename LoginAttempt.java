/**
 * Represents a single login attempt.
 * Implements Comparable to support sorting (by username).
 */
public class LoginAttempt implements Comparable<LoginAttempt> {
    private String username;
    private String ipAddress;
    private String timestamp;
    private boolean success;

    /**
     * Constructs a LoginAttempt.
     *
     * @param username  username attempting login
     * @param ipAddress source IP address
     * @param timestamp timestamp string
     * @param success   whether the login was successful
     */
    public LoginAttempt(String username, String ipAddress, String timestamp, boolean success) {
        this.username = username;
        this.ipAddress = ipAddress;
        this.timestamp = timestamp;
        this.success = success;
    }

    /** @return username */
    public String getUsername() { return username; }

    /** @return IP address */
    public String getIpAddress() { return ipAddress; }

    /** @return timestamp */
    public String getTimestamp() { return timestamp; }

    /** @return whether attempt was successful */
    public boolean wasSuccessful() { return success; }

    /**
     * Comparison by username (case-insensitive). Used by custom sort.
     *
     * @param other other LoginAttempt to compare to
     * @return standard compareTo contract
     */
    @Override
    public int compareTo(LoginAttempt other) {
        return this.username.compareToIgnoreCase(other.username);
    }

    /**
     * Returns a readable description of the attempt.
     *
     * @return string representation
     */
    @Override
    public String toString() {
        return "User: " + username +
               " | IP: " + ipAddress +
               " | Time: " + timestamp +
               " | Success: " + success;
    }
}
