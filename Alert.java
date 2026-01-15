/**
 * Simple Alert object representing a generated alert.
 */
public class Alert {
    private String ipAddress;
    private String message;
    private String timestamp;

    /**
     * Constructs an Alert.
     *
     * @param ipAddress offending IP address
     * @param message   description of alert
     * @param timestamp alert time
     */
    public Alert(String ipAddress, String message, String timestamp) {
        this.ipAddress = ipAddress;
        this.message = message;
        this.timestamp = timestamp;
    }

    /** @return IP address */
    public String getIpAddress() { return ipAddress; }

    /** @return message */
    public String getMessage() { return message; }

    /** @return timestamp */
    public String getTimestamp() { return timestamp; }

    @Override
    public String toString() {
        return "[ALERT] IP: " + ipAddress + " | " + message + " | Time: " + timestamp;
    }
}
