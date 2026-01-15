SUSPICIOUS LOGIN DETECTION SYSTEM

Final Project Documentation – Data Structures

1. Program Name
Suspicious Login Detection System. A cybersecurity tool that tracks login attempts, detects suspicious behavior and manages security alerts using core data structures.

2. Program Description
This program simulates a simplified SOC (Security Operations Center) alerting tool.
It allows the user to do these:
• Log user login attempts
• Detect suspicious logins
• Maintain alert queues
• Sort log entries
• Undo alert dismissals
The system uses the required data structures: List, Map, Queue, Stack, Custom Objects
and a sorting algorithm using Comparable.

3. Features Implemented
Feature 1 — Add Login Attempt
• User enters:
1. Username
2. IP address
3. Success/failure
• System stores login in a List
• It adds login info to a Map of usernames → attempts
• If suspicious, the login is added to an Alert Queue

Suspicious criteria include:
• Login failed
• Login from a new IP address
• Multiple logins attempt in a short time

Feature 2 — Display All Logs
Shows every login attempt stored in the List.

Feature 3 — Sort Logs (By Username)
Implements a custom sorting algorithm (Bubble Sort) on Login attempt objects.
Login Attempt implements Comparable to compare usernames alphabetically.

Feature 4 — View Pending Alerts
Use a Queue to show alerts in FIFO order.

Feature 5 — Dismiss Next Alert
• Removes the next alert from the Queue
• Pushes the alert onto a Stack
• Allows undo capability
Represents SOC Tier 1 analysts clearing alerts.

Feature 6 — Undo Alert Dismissal
• Pops the most recent alert from the Stack
• Returns it to the Queue

Feature 7 — Exit Program

4. Data Structures Projects Requirements
Requirement  Implemented Using        Where Used?
List         ArrayList<LoginAttempt>  Stores all login attempts
Map          HashMap<String, Integer> Counts login attempts per user
Queue        LinkedList<LoginAttempt> Pending alerts (FIFO)
Stack        Stack<LoginAttempt>      Undo dismissed alerts

Requirement          Implemented Using        Where Used?
Custom Object        LoginAttempt class      Holds username, IP timestamp, status
Custom Sorting Algorithm Bubble Sort         Sorts login attempts by username
Comparable            implements Comparable<LoginAttempt> Required for custom sort

5. Key Classes & Their Responsibilities
# LoginAttempt (Custom Object)
Variables:
• String username
• String ip
• boolean success
• long timestamp
Functions:
• Constructor
• Getters
• compareTo() (for sorting by username)
• toString()
# Main Responsible for:
• Menu
• User input
• Managing all data structures
• Detecting suspicious activity
• Sorting logs
• Dismissing and undoing alerts

6. Pseudocode for Main Operations
Add Login Attempt
read username, ip, success
create LoginAttempt object
add to logList
update loginCountMap
if suspicious → add to alertQueue

Dismiss Next Alert
if queue is empty:
 print "No alerts"
else:
 alert = queue.poll()
 stack.push(alert)

Undo Alert Dismissal
if stack is empty:
 print "Nothing to undo"
else:
 alert = stack.pop()
 queue.add(alert)

Sort Logs (Bubble Sort)
for i from 0 to n-1:
 for j from 0 to n-i-1:
 if log[j] > log[j+1]:
 swap them

7. Example Output

===== SUSPICIOUS LOGIN DETECTION SYSTEM =====
1. Add Login Attempt
2. Display All Logs
3. Sort Logs (by Username)
4. View Pending Alerts
5. Dismiss Next Alert
6. Undo Alert Dismissal
7. Save Data
8. Load Data
9. Exit
Select option:
10. Conclusion
This program fulfills all requirements for the final project while applying real cybersecurity concepts related to SOC analysis, login monitoring, alert management, and 
suspicious behavior detection.
It demonstrates:
• Practical use of data structures
• Custom object-oriented design
• Realistic alert handling logic
• A working custom sorting algorithm
