# **Illumio Technical Assessment**

Thank you to my interviewers that will be reading this `:D`

## Thought process while reading

* There are 14 different types of data in a version 2 flow log.

* We only care about the dstport and protocol since that is what is used to get the corresponding tag

* dstport is 7th element (index 6)
* protocol is 8th element (index 7)

* tag_mappings tells us combinations of dstport and protocol which will end up with a tag

### **Processing Flow**

1. Load tag mappings:
   * Read CSV file
   * Store in dictionary with (dstport, protocol) as key

2. Process flow logs:
   * Parse each line into FlowLog object
   * Convert protocol number to string (6 -> tcp, 17 -> udp, etc.)
   * Look up tag in mappings
   * increment port/protocol combinations
   * increment tag occurrences

3. Write results:
   * Generate two CSV files
   * Sort results for consistent output
   * Use proper CSV formatting

### Data Structures used

1. FlowLog dataclass:
   * Represents a single flow log entry
   * Contains all 14 fields for type safety and readability
   * Makes it easier to access dstport and protocol

2. TagMapping dataclass:
   * Represents a single tag mapping rule
   * Contains dstport, protocol, and tag
   * Helps validate mapping data structure

3. ProcessingResults dataclass:
   * Holds the final counts
   * Contains tag_counts and port_protocol_counts
   * Makes it easy to pass results between functions
  
### Considerations
  
  1. There currently there is no easy way to convert the protocol numbers to it's respective name,
I grabbed this snippet from this URL that makes it easier: <https://pymotw.com/2/socket/addressing.html>
