# FReD - Firewall Ruleset Distributor
FReD, or how its friends call it: Freddy, is a tool to distribute central firewall rules to decentralized filter points in an industrial network.

**Why would you need such a tool you ask?**
Well, it's because software-based firewalls tend to have a poor performance and we definately don't want that in our time critical, industrial environments, even though that's the common case right now.
Thus, Freddy redistributes the filter logic of software firewalls to switches with filter capacities in a network.
Why?
Because switches with ACLs do so in hardware - in real time.
If you want to know more, please refer to our paper referenced [here](tbd.).


## Licence and Citation
FReD is licensed under the terms of the MIT license.

Our paper was submitted to the [WFCS 2025](https://wfcs25.uni-rostock.de) and is currently under review.
If you use FReD in one of your papers, please cite:
```
tbd.
```


## How to get started
To install Freddy on your machine, you first need to install its requirements.

### GeNESIS
FReD requires the input of topologies, firewall configurations and traffic. The input format is alligned with the output format of GeNESIS. Therefore, FReD has the main requirement to GeNSIS. You can find GeNESIS and a tutorial on it here: [GeNESIS v1.1 on GitHub](https://github.com/hs-esslingen-it-security/hses-GeNESIS/tree/v1.1)

### Additional Requirements
You can install the additional requirements by executing:
```
pip3 install -r <your-local-fred-project-path>/requirements.txt
```

### Install FReD
When successful, you can install Freddy with:
```
pip3 install <your-local-fred-project-path>
```

To test, whether Freddy was installed correctly, you can execute a small sample run using:
```
python3 <your-local-fred-project-path>/main.py -f
```
When doing so, Freddy will perform a full distribution cycle with the example project `<your-local-fred-project-path>/resources/default`.
The output of this sample run will be saved in `<your-local-fred-project-path>/output`.


## How to use
When executing Freddy, a user can provide different arguments:
```
optional arguments:
  -i INPUT_LOCATION, --input_location INPUT_LOCATION
  -o OUTPUT_LOCATION, --output_location OUTPUT_LOCATION
  -l LABEL, --label LABEL
  -f, --force_all_runs
```

### input_location
The most important argument is the `-i` flag, as Freddy requires a specific input: a full [GeNESIS](https://github.com/hs-esslingen-it-security/hses-GeNESIS) evaluation scenario.
This includes a network topology, packet traces, and security configurations.
To feed this evaluation scenario into Freddy, provide it by passing the path to it using the `-i` tag:
```
python3 <your-local-fred-project-path>/main.py -i <your-local-genesis-project-path>/output/<evaluation_scenaro> -f
```
> Be shure to pass the path to all the evaluation scenarios of a single GeNESIS-execution, e.g., `<your-local-fred-project-path>/resources/default`, and not a specific iteration, e.g., `<your-local-fred-project-path>/resources/default/240-53-741`. Otherwise Freddy will raise an exception! It's a picky eater.

The default value for this argument is set to `<your-local-fred-project-path>/resources/default`.

### output_location
Freddy enables users to specify a custom output location.
For example, passing `-o <your-specified-output-location>` will cause Freddy to save all its outputs in `<your-specified-output-location>`.
> Note: if the specified output location does not exist, Freddy will create that location if possible.

The default value for this argument is set to `<your-local-fred-project-path>/output`

### label
You can further structure Freddys output by specifying a label.
For example, executing Freddy with `-l test_run` will create the folder `<your-specified-output-location>/test_run` and save the outputs there.

The default value for this argument is set to `"default_config"`.

### force_all_runs
Whenever Freddy is finished distributing a GeNESIS evaluation scenario, it leaves a `.fred-footprint` file in the corresponding iteration folder.
If Freddy encounters such a file in a future run, it will skip that iteration, unless `-f` was provided in that run.

The default value for this argument is set to `False`.

## What to expect
Per execution, Freddy outputs the following folder structure:
```
[y-m-d-H-M-S]
   |- [X-Y-Z]
      |- 00_base
         |- graphs
            |- graph.graphml
         |- results
            |- packet_traces.csv
         |- rulesets
            |- iptables
               |- [router_id]-iptables-save
               |- ...
      |- 01_sorted
         |- graphs
            |- graph.graphml
         |- results
            |- packet_traces.csv
         |- rulesets
            |- iptables
               |- [router_id]-iptables-save
               |- ...
      |- 02_drop_only_distribution
         |- graphs
            |- graph.graphml
         |- results
            |- packet_traces.csv
         |- rulesets
            |- iptables
               |- [router_id]-iptables-save
               |- ...
      |- 03_accept_only_distribution
         |- graphs
            |- graph.graphml
         |- results
            |- packet_traces.csv
         |- rulesets
            |- iptables
               |- [router_id]-iptables-save
               |- ...
      |- packets.csv
      |- runtime_measurements.csv
   |- ...
   |- .genesistag
   |- config.json
```
The root folder is named after the timestamp, the execution was started.
This timestamp folder in turn contains further folders for each GeNESIS evaluation iteration processed.
These iteration-folders contain the actual output, structured by the different distribution steps of Freddy.
For each distribution step, Freddy saves the graph structure after the application of the distribution step as `.graphml` file.
Note, the actual topology does not change between the steps.
However, the rulesets and ACLs are also stored in these files.
Therefore, the different rule positions and filter utilizations of individual devices per distribution step can be easily analyzed in these files.

Additionally, Freddy stores all rulesets and ACLs in iptables-save format inside the rulesets/iptables folders of each generation step for better readability.

Also, for each distribution step, Freddy calculates traffic latency predictions based on topology, ACL and firewall states.
These latency predictions are saved in the `packet_traces.csv` files located inside the results folders of each distribution step.