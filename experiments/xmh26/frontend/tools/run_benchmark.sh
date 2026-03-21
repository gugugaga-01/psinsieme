#!/bin/bash

# Define arrays for the number of participants and the size of the set
number_of_parties=(5)
set_sizes=(5 7 9 11 13)

# Set the output file
# output_file="output/benchmark_output.txt"
# mkdir -p output
# >> "$output_file"


# Loop over different values of n
for n in "${number_of_parties[@]}"; do
    # Loop over different values of m
    for m in "${set_sizes[@]}"; do
        date
        
        # Create a new shell script file
       script_file=./tools/"benchmark.sh"
        
        # Print prompt messages to the script file
        echo "#!/bin/bash" > "$script_file"
        echo "# Auto-generated script for n = $n, m = $m" >> "$script_file"
        echo "" >> "$script_file"
        
        # Loop over the range of participant identifiers and write commands to the script file
        for ((p=0; p<$n; p++)); do
            echo "./bin/frontend.exe -n $n -m $m -p $p &" >> "$script_file"
        done
        
        # Assign executable permission to the script file
        chmod +x "$script_file"
        
        # Check if previous processes have terminated
        while pgrep frontend.exe >/dev/null; do
            echo "Previous instances of frontend.exe are still running. Waiting..."
            sleep 10 # Check every 5 seconds
        done
        
        echo "Previous instances of frontend.exe have been terminated. Starting new instances..."
        
        # Start new frontend.exe processes
        sh ./"$script_file" 
        
        # Wait for a specified time
        sleep_time=20s # adjust this value as needed
        sleep $sleep_time
        
    done

done
