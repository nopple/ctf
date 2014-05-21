#Information

This was an unintended use-after-free vulnerability in the variable processing commands (set/show). Exploitation is straight-forward:

* Trigger the invalid state by adding and removing variables
* Cause a 16-byte allocation with controlled data to fill the freed structure
 * make a fake variable structure with a pointer to the password as the key and value
 * controlled heap data via strdup() on the argument to a command
* show variables to dump the enable password
* profit

#Relevant Structures
`struct variable { char* key, char* value, variable *flink, variable *blink }`

#Execution Log

```
 oooooooo8 oooo        o88    o8                                       
888         888ooooo   oooo o888oo  oooooooo8    ooooooo     ooooooo   
 888oooooo  888   888   888  888   888ooooooo  888     888 888     888 
        888 888   888   888  888           888 888         888     888 
o88oooo888 o888o o888o o888o  888o 88oooooo88    88ooo888    88ooo88   
                                                                       
Welcome to Shitsco Internet Operating System (IOS)
For a command list, enter ?
$ 
$ 
$ 
$ 
$ 
���� is not set.
$ 
bruT3m3hard3rb4by: bruT3m3hard3rb4by
$ 
Enable password: "bruT3m3hard3rb4by"
Authentication Successful
# 
The flag is: Dinosaur vaginas

# 
```
