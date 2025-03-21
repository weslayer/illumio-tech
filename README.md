# **Illumio Technical Assessment**

In this assessment, I will be:

* Parsing AWS VPC Verison 2 logs
* Tagging the log for the combination of dstport, protocol according to the tag_mappings
* Outputting the occurences of the combination of dstport, protocol
* Outputting the occurences for tags

To run this project, 
1. Input desired flow logs in the input directory
2. Input desired mappings in the mappings directory
3. Run `python main.py` in the main `illumio-tech` directory terminal

Thank you to my interviewers that will be reading this `:D`

## Thought process while reading

* There are 14 different types of data in a version 2 flow log.
* We only care about the dstport and protocol (index 6, 7)
* combin of dstport, protocol -> tag

### **Processing Flow**

1. Load tag mappings:
   * Read CSV file
   * Store in dictionary with (dstport, protocol) as key

2. Process flow logs:
   * Parse each line into FlowLog dataclass
   * Convert protocol number to string (6 -> tcp, 17 -> udp, etc.)
   * Look up tag in mappings
   * increment port/protocol combinations and tag occurrences

3. Write results:
   * Generate two CSV files
   * Sort results -> write

### Data Structures used

1. FlowLog dataclass:
   * Represents a single flow log entry
   * Contains all 14 fields for type safety and readability
   * Makes it easier to access dstport and protocol

2. TagMapping dataclass:
   * Represents a single tag mapping rule
   * Contains dstport, protocol, and tag

3. ProcessingResults dataclass:
   * Holds the final tag_counts and port_protocol_counts
  
### Testing

I used `pytest` for testing which allows for module testing in Python. 

I tested many cases and functions:
* creation of testing files
* parsing flow logs
* protocol number -> protocol name
* expected tag count
* untagged flow logs
* mixed tags
* unknown protocol
* empty flow log file
  
### Considerations
  
* There currently is no easy way to convert the protocol numbers to its respective name,
      I grabbed this snippet from this URL that makes it easier: <https://pymotw.com/2/socket/addressing.html>
  * Converting the protocol # to name is necessary since the output requires the number as its string form, and the lookup table uses the string form.
