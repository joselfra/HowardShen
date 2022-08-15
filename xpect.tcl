#!/usr/bin/expect
exp_internal 0
set timeout 30
log_user 0
set NA_prompt "NA>"
set NULL_VALUE ThisRepresentANullValueThatIsDifferentThanEmptyString


proc read_pwd_db {cred_file} {
	set d [dict create]
	
	if {[catch {set fd [open $cred_file r]} error]} {
		puts "$error"
		return $d
	}
	
	while 1 {
		set line [read_a_line $fd]
		if {$line eq ""} {
			break
		}
		
		if {![regexp {^RULENAME:(.*)$} $line match rulename]} {
			puts "Expecting RULENAME"
			exit
		}
		
		set line [read_a_line $fd]
		if {![regexp {^USERNAME:(.*)$} $line match username]} {
			puts "Expecting USERNAME"
			exit
		}

		set line [read_a_line $fd]
		if {![regexp {^PASSWORD:(.*)$} $line match password]} {
			puts "Expecting PASSWORD"
			exit
		}
		
		dict set d $rulename USERNAME $username
		dict set d $rulename PASSWORD $password
	}
	
	close $fd
	return $d
}


proc read_a_line {fd} {
	set line ""
	
	while 1 {
		set ret [gets $fd line]
		if {$ret < 0} {
			break
		} 

		set line [string trim $line]
		if {$line ne "" && ![regexp {^#.*} $line]} {
			break
		}
	}
		
	return $line
}


proc read_conn_interactions {conn_file} {
	puts "Reading connection interaction file $conn_file"
	
	if {[catch {set fd [open $conn_file r]} error]} {
		puts "$error"
		return $d
	}
	
	set d [dict create]
	
	while {1} {
		if {[gets $fd line] < 0} {
			break
		}
		
		if {![regexp {^PATTERN:(.*)$} $line match pattern]} {
			puts "Expecting PATTERN"
			exit
		}
		
		if {[gets $fd line] < 0 || ![regexp {^RESPONSE:(.*)$} $line match response]} {
			puts "Expecting RESPONSE"
			exit
		}	
		
		dict set d $pattern $response
	}
	
	close $fd
	return $d
}


proc dev_login {ip conn_args context} {
	upvar $context ctx
	global NULL_VALUE spawn_id
	
	set proto [dict get $conn_args PROTO]
	set username [dict get $conn_args USERNAME]
	set password [dict get $conn_args PASSWORD]
	set login_prompt [dict get $conn_args LOGIN_PROMPT]
	set enable_prompt [dict get $conn_args ENABLE_PROMPT]

	set port {}
	
	if {$proto eq "SSH"} {
		set opt "-q -o StrictHostKeyChecking=no"
		if {[dict exists $conn_args CIPHER]} {
			set opt "$opt -c [dict get $conn_args CIPHER]"
		}
		if {[dict exists $conn_args PORT]} {
			set opt "$opt -p [dict get $conn_args PORT]"
		}
		set cmd "ssh $opt $username@$ip"
	} elseif {$proto eq "TELNET"} {
		set cmd "telnet $ip"
		if {[dict exists $conn_args PORT]} {
			set cmd "$cmd [dict get $conn_args PORT]"
		}
	} else {
		append_jlog "Connection type must be SSH or TELNET"
		return -1
	}

	set exp_str "timeout {set imatch 0}"
	set exp_str "$exp_str eof {set imatch 1}"
	set exp_str "$exp_str {closed by remote host} {set imatch 2}"
	set exp_str "$exp_str -re {$login_prompt} {set imatch 3}"
	set exp_str "$exp_str -re {$enable_prompt} {set imatch 4}"
	set exp_str "$exp_str {*sername:} {set imatch 5}"
	set exp_str "$exp_str {User:} {set imatch 6}"
	set exp_str "$exp_str {*assword:} {set imatch 7}"
	
	if {[dict exists $conn_args INTERACTION]} {
        set conn_file [lindex $argv $i]
		set interaction_dict [read_conn_interactions $conn_file]

		set i 7
		dict for {pattern response} $interaction_dict {
			set exp_str "$exp_str {$pattern} { set imatch $i }"
			set response_array($i) $response
			incr i
		}
	}
	
	append_jlog "\n>>>>>> Connecting to $ip, USERNAME=$username PASSWORD=$password......"

	eval spawn $cmd
	append_jlog "spawn $cmd"
	
	while {1} {
		eval "expect {
				$exp_str
			 }"
			 
		if {$imatch == 0} {
			return [dict create STATUS FAILED MESSAGE "Connection request timed out"]
		} elseif {$imatch == 1} {
			return [dict create STATUS FAILED MESSAGE "Connection returned EOF"]
		} elseif {$imatch == 2} {
			return [dict create STATUS FAILED MESSAGE "Connection closed by remote host"]
		} elseif {$imatch == 3 || $imatch == 4} {
			break
		} elseif {$imatch == 5 || $imatch == 6} {
			# Wrap send command inside a 'catch" statement to protect against bad connection
			if {[catch {send "$username\r"} output] != 0} {
				return [dict create STATUS FAILED MESSAGE "An error occurred: $output"]
			}
		} elseif {$imatch == 7} {
			# Wrap send command inside a 'catch" statement to protect against bad connection
			if {[catch {send "$password\r"} output] != 0} {
				return [dict create STATUS FAILED MESSAGE "An error occurred: $output"]
			}
		} else {
			send "$response_array($imatch)\r"
		}
	}

	if {$imatch == 3 && $enable_prompt ne $NULL_VALUE} {
		if {[dict exists $conn_args ENABLE_PWD]} {
			set enable_pwd [dict get $conn_args ENABLE_PWD]
		} else {
			set enable_pwd $password
		}

		send "enable\r"
		expect {
			timeout {
				return [dict create STATUS FAILED MESSAGE "Failed to enter ENABLE mode"]
			}
			"assword:" {
				send "$enable_pwd\r"
				exp_continue
			}
			-re "$enable_prompt" {
				set imatch 4
			}
		}
	}
	
	dict set ctx VARIABLES SPAWN_ID $spawn_id
	
	if {$imatch == 4} {
		return [dict create STATUS "ENABLED" MESSAGE "Successfully entered ENABLE mode"]	
	} else {
		return [dict create STATUS "ENTERED" MESSAGE "Successfully logged in"]
	}
}


# Return value:
# 0  : Continue to the next command
# 1  : End config job with success
# -1 : End with fail
# 
proc execute_task_list {context task_list depth} {
	upvar $context ctx
	
	foreach task $task_list {
		set xcode [execute_task ctx $task $depth]
		if {$xcode != 0} {
			return $xcode
		}
	}	
	
	return 0
}


# Return value:
# 0  : Continue to the next command
# 1  : End config job with success
# -1 : End with fail
# 
# execution_data:
#   - prompt
#   - cmd_result (list)
#   
proc execute_task {context task depth} {
	upvar $context ctx
	
	set action [dict get $task ACTION]

	if {$action eq "CONNECT"} {
		return [execute_connect_action ctx $task $depth]
	} elseif {$action eq "DISCONNECT"} {
		return [execute_disconnect_action ctx $task $depth]
	} elseif {$action eq "SEND"} {
		return [execute_send_action ctx $task $depth]
	} elseif {$action eq "EXEC"} {
		return [execute_exec_action ctx $task $depth]
	} elseif {$action eq "EXPR"} {
		return [execute_expr_action ctx $task $depth]
	} elseif {$action eq "EVAL"} {
		return [execute_eval_action ctx $task $depth]
	} elseif {$action eq "REGEX"} {
		return [execute_regex_action ctx $task $depth]
	} elseif {$action eq "CALL"} {
		return [execute_call_action ctx $task $depth]
	} else {
		send_user "Invalid command $action\n"
		exit -1
	}
}

	
proc execute_connect_action {context task depth} {
	upvar $context ctx
	global NULL_VALUE gd_pwd_db

	set conn_opts [dict get $task OPTIONS]
	set conn_args [dict get $task ARGUMENTS]

	if {![dict exists $conn_args LOGIN_PROMPT]} {
		append_jlog "Missing login prompt"
		return -1
	}

	if {![dict exists $conn_args ENABLE_PROMPT]} {
		dict set conn_args ENABLE_PROMPT $NULL_VALUE
	}
	
	# use ip address on the argument list instead of the device ip - ${DEV_IP} 
	# This is needed in case a jumpserver is used
	#
	if {[dict exists $conn_args IP]} {
		set ip [dict get $conn_args IP]
		dict set ctx VARIABLES DEV_IP $ip
	} else {
		set ip [dict get $ctx VARIABLES DEV_IP]	
	}

	if {[dict exists $conn_args PROTO]} {
		set proto [dict get $conn_args PROTO]
	} else {
		dict set conn_args PROTO SSH
	}
	
	if {![dict exists $conn_args USERNAME]} {
		append_jlog "\nUSERNAME not specified. Will use info from credentials DB !!"	
		dict set ctx CONN_STATUS FAILED
		
		dict for {rulename cred} $gd_pwd_db {
			dict set conn_args USERNAME [dict get $cred USERNAME]
			dict set conn_args PASSWORD [dict get $cred PASSWORD]
			
			set ret [dev_login $ip $conn_args ctx]
			append_jlog [dict get $ret MESSAGE]

			if {[dict get $ret STATUS] ne "FAILED"} {
				dict set ctx CONN_STATUS [dict get $ret STATUS]
				dict set ctx RULENAME $rulename
				dict set ctx VARIABLES DEV_USR [dict get $conn_args USERNAME]
				dict set ctx VARIABLES DEV_PWD [dict get $conn_args PASSWORD]
				break
			}
		}		
	} elseif {![dict exists $conn_args PASSWORD]} {
		append_jlog "\nPASSWORD not specified. Will use info from credentials DB !!"	
		dict set ctx CONN_STATUS FAILED
		set user [dict get $conn_args USERNAME]
		
		dict for {rulename cred} $gd_pwd_db {
			if {$user == [dict get $cred USERNAME]} {
				dict set conn_args USERNAME $user
				dict set conn_args PASSWORD [dict get $cred PASSWORD]
			
				set ret [dev_login $ip $conn_args ctx]
				append_jlog [dict get $ret MESSAGE]

				if {[dict get $ret STATUS] ne "FAILED"} {
					dict set ctx CONN_STATUS [dict get $ret STATUS]
					dict set ctx RULENAME $rulename
					dict set ctx VARIABLES DEV_USR [dict get $conn_args USERNAME]
					dict set ctx VARIABLES DEV_PWD [dict get $conn_args PASSWORD]
					break
				}
			}
		}		
	} else {
		set ret [dev_login $ip $conn_args ctx]
		append_jlog [dict get $ret MESSAGE]
		dict set ctx CONN_STATUS [dict get $ret STATUS]
		dict set ctx RULENAME "Command-line"
		dict set ctx VARIABLES DEV_USR [dict get $conn_args USERNAME]
		dict set ctx VARIABLES DEV_PWD [dict get $conn_args PASSWORD]
	}
	
	if {[dict get $ret STATUS] eq "ENTERED"} {
		dict set ctx VARIABLES DEV_PROMPT [dict get $conn_args LOGIN_PROMPT]
	} else {
		dict set ctx VARIABLES DEV_PROMPT [dict get $conn_args ENABLE_PROMPT]
	}
	
	if {[dict get $ctx CONN_STATUS] eq "FAILED"} {
		if {[dict exists $task XERROR]} {
			set error_task [dict get $task XERROR]
			set next_list [dict get $error_task TASK_LIST]
			set ret [execute_task_list ctx $next_list [expr $depth+1]]
			if {$ret != 0} {
				return $ret
			}
			return [dict get $error_task XCODE]
		}
		return -1
	}
	return 0
}


proc execute_disconnect_action {context task depth} {
	upvar $context ctx
	
	append_jlog "\n>>>>> Disconnecting from device [dict get $ctx VARIABLES DEV_IP]"
	catch {close -i [dict get $ctx VARIABLES SPAWN_ID]}
}


proc execute_send_action {context task depth} {
    global expect_out timeout spawn_id NULL_VALUE
	upvar $context ctx

	if {![dict exists $ctx VARIABLES SPAWN_ID]} {
		append_jlog "Not connected to device. Aborting"
		return -1
	}
	
	set spawn_id [dict get $ctx VARIABLES SPAWN_ID]
	set prompt [dict get $ctx VARIABLES DEV_PROMPT]

	set opt_dict [dict get $task OPTIONS]
	if {[dict exists $opt_dict N]} {
		set max_loop [dict get $opt_dict N]
	} else {
		set max_loop 1
	}

	# Retrieve send_str and perform variable substitutions 
	set send_str [dict get $task CMD_STR]
	set send_str [var_substitution $ctx $send_str]
	
	append_jlog "\n>>>>>> SEND:${send_str}"

	# Default size of expect_buffer is 2000, which is too small for commands that produce large output
	# match_max is a expect function!
	match_max 2000000
	# Quote: I've found that match_max can cause expect_out(buffer) to become undefined. 
	# Redefine it after calling match_max to get round this.
	set expect_out(buffer) {}

	# send the command
	if {[catch {send $send_str\r} err]} {
		append_jlog "Failed to send $send_str: $err"
		return -1
	}

	set to [dict get $opt_dict T]
	
	# expect the default prompt if both the following 2 conditions are met:
	# 1. The SEND command doesn't have an XPECT clause
	# 2. This is not an exp_continue type of SEND command -- this is the 
	#    case when the SEND command itself is a subtask
	#
	if {![dict exists $task XLIST]} {
		if {![dict exists $task LOOP]} {
			expect {
				-timeout $to $prompt { 
					append_jlog "Seeing:${prompt}" 
				}
				timeout { 
					append_jlog "Expecting '${prompt}' but not found"
					return -1
				}
			}
		}
		return 0
	}
	
	set xlist [dict get $task XLIST]
	set to_op "-timeout [dict get $opt_dict T]"
	set exp_str {}
	set e_list {}
	
	# Add normal "expect" statements
	for {set i 0} {$i < [llength $xlist]} {incr i} {
		set x [lindex $xlist $i]
		set e [var_substitution $ctx [dict get $x EXP]]
		set ops [options_to_string [dict get $x OPTIONS]]
		set exp_str "$exp_str $to_op $ops {$e} {set imatch $i}"
		lappend e_list $e

		set loopcount($i,cur) 0
		if {[dict exists $x OPTIONS N]} {
			set loopcount($i,max) [dict get $x OPTIONS N]
		} else {
			set loopcount($i,max) 3
		}
	}

	if {[dict exists $task XOTHER]} {
		set loopcount(other,cur) 0
		if {[dict exists $task XOTHER OPTIONS N]} {
			set loopcount(other,max) [dict get $task XOTHER OPTIONS N]
		} else {
			set loopcount(other,max) 3
		}
	}
	
	# add "expect" error handling
	set exp_str "$exp_str timeout {set imatch -2} eof {set imatch -1}"
	
	# Required for devices that do not support terminal length 0
	set exp_str "$exp_str -regexp {(.*)\\-\\-\\s?More\\s?\\-\\-} {set imatch -3}"
	
	# initialize MORE_BUFFER
	dict set ctx MORE_BUFFER {}	

	# protect against weird full_beffer issue
	set exp_str "$exp_str  full_buffer {
					puts {\n\n!!! full_buffer !!!\n\n}
					exit 
				 }"

	while {1} {
		eval "expect { 
			$exp_str 
		  }"			

		if {$imatch >= 0} {
			incr loopcount($imatch,cur)
			
			set x [lindex $xlist $imatch]
			append_jlog "Seeing:[lindex $e_list $imatch]"		

			process_cgroup_list ctx [dict get $x CGROUPS]
			
			# expect_buffer clean up:
			# 	Step 1: Force "expect" to read whatever is remaining in the channel into expect_buffer
			# 	Step 2: Throw away the content of expect_buffer. Enclose "expect *" to protect against EOF
			expect -timeout 1 $NULL_VALUE
			catch {expect *}
		
			set next_list [dict get $x TASK_LIST]
			set ret [execute_task_list ctx $next_list [expr $depth+1]]
			if {$ret == 0} {
				set ret [dict get $x XCODE]			
				if {$ret == 2} {
					if {$loopcount($imatch,cur) < $loopcount($imatch,max)} {
						continue
					} 
					append_jlog "Maximum # of loops exceeded"
					set ret -1
				}
			}
			break
		}  elseif {$imatch == -3} {
			# Save buffer content for later use. This is required on devices 
			# that do not support terminal length 0,  
			set buf [dict get $ctx MORE_BUFFER]
			dict set ctx MORE_BUFFER "$buf$expect_out(1,string)"
			send { }
			continue
		} else {
			if {$imatch == -2} {
				append_jlog "Timeout encountered"	
			} elseif {$imatch == -1} {
				append_jlog "EOF encountered"		
			}
			
			if {![dict exists $task XOTHER]} {
				send_user "\nUnhandled exception"
				set ret -1
				break
			} 
			
			append_jlog "No match found. Entering XOTHER"
			
			incr loopcount(other,cur)

			# Throw away the content of expect_buffer
			expect *

			set other_task [dict get $task XOTHER]
			set next_list [dict get $other_task TASK_LIST]
			set ret [execute_task_list ctx $next_list [expr $depth+1]]
			if {$ret == 0} {
				set ret [dict get $other_task XCODE]						
				if {$ret == 2} {
					if {$loopcount(other,cur) < $loopcount(other,max)} {
						continue
					} 
					append_jlog "Maximum # of loops exceeded"
					set ret -1
				}
			}
			break
		}		
	}
		
	return $ret
}


proc execute_exec_action {context task depth} {
    global expect_out timeout spawn_id NULL_VALUE
	upvar $context ctx
	
	set opt_dict [dict get $task OPTIONS]
	
	if {[dict exists $opt_dict N]} {
		set max_loop [dict get $opt_dict N]
	} else {
		set max_loop 1
	}
	
	set to [dict get $opt_dict T ]
	set to_op "-timeout $to"
	set exp_str {}
	
	if {[dict exists $task XLIST]} {
		set xlist [dict get $task XLIST]
	} else {
		# if -and ONLY if- normal "expect" statement is missing, add bash prompt "expect"
		set e "(.*)$"
		set o [dict create R 1]
		lappend xlist [dict create EXP $e OPTIONS $o TASK_LIST [list] XCODE 0]
	}
	
	# Add normal "expect" statements
	for {set i 0} {$i < [llength $xlist]} {incr i} {
		set x [lindex $xlist $i]
		set e [dict get $x EXP]	
		set ops [options_to_string [dict get $x OPTIONS]]
		set exp_str "$exp_str $to_op $ops {$e} {set imatch $i}"
		
		set loopcount($i,cur) 0
		if {[dict exists $x OPTIONS N]} {
			set loopcount($i,max) [dict get $x OPTIONS N]
		} else {
			set loopcount($i,max) 3
		}
	}

	if {[dict exists $task XOTHER]} {
		set loopcount(other,cur) 0
		if {[dict exists $task XOTHER OPTIONS N]} {
			set loopcount(other,max) [dict get $task XOTHER OPTIONS N]
		} else {
			set loopcount(other,max) 3
		}
	}
	
	# add "expect" error handling
	set exp_str "$exp_str timeout {set imatch -2} eof {set imatch -1}"
	set exp_str "expect { 
					$exp_str 
				}"
	set exp_str [var_substitution $ctx $exp_str]

	# Retrieve exec_str and perform variable substitutions
	set exec_str [dict get $task CMD_STR]
	set exec_str [var_substitution $ctx $exec_str]

	append_jlog "\n>>>>>> EXEC:$exec_str"
	set exec_str "spawn /bin/sh -c {$exec_str}"

	# executing the command
	if {[catch {eval $exec_str} err]} {
		append_jlog $err
		return -1
	}
	
	# EXEC command always requires with a new context!!
	# Replace the login prompt with Bash prompt
	#
	set new_ctx [dict replace $ctx]
	dict set new_ctx VARIABLES SPAWN_ID $spawn_id 
	dict set new_ctx VARIABLES DEV_PROMPT $ 
	
	while {1} {
		if {[catch {eval $exp_str} err]} {
			append_jlog $err
			break
		}
		
		if {$imatch >= 0} {
			incr loopcount($imatch,cur)

			set x [lindex $xlist $imatch]
			append_jlog "Seeing:[dict get $x EXP]"


			process_cgroup_list ctx [dict get $x CGROUPS]
			
			# expect_buffer clean up:
			# 	Step 1: Force "expect" to read whatever is remaining in the channel into expect_buffer
			# 	Step 2: Throw away the content of expect_buffer. Enclose "expect *" to protect against EOF
			expect -timeout 1 $NULL_VALUE
			catch {expect *} 
		
			set next_list [dict get $x TASK_LIST]
			set ret [execute_task_list new_ctx $next_list [expr $depth+1]]
			if {$ret == 0} {
				set ret [dict get $x XCODE] 
				if {$ret == 2} {
					if {$loopcount($imatch,cur) < $loopcount($imatch,max)} {
						continue
					}
					append_jlog "Maximum # of loops exceeded"
					set ret -1
				}
			}
			break
		} else {
			if {$imatch == -2} {
				append_jlog "Timeout encountered"		
			} elseif {$imatch == -1} {
				append_jlog "EOF encountered"		
			}

			if {![dict exists $task XOTHER]} {
				append_jlog "\nUnhandled exception"
				set ret -1
				break
			}
			
			incr loopcount(other,cur)
			
			# Throw away the content of expect_buffer
			expect *

			append_jlog "No match found. Entering XOTHER"
			set other_task [dict get $task XOTHER]
			set next_list [dict get $other_task TASK_LIST]
			set ret [execute_task_list new_ctx $next_list [expr $depth+1]]
			if {$ret == 0} {
				set ret [dict get $other_task XCODE]			
				if {$ret == 2} {
					if {$loopcount(other,cur) < $loopcount(other,max)} {
						continue
					}
					append_jlog "Maximum # of loops exceeded"
					set ret -1
				}
			}
			break
		}
	}
		
	return $ret
}


proc execute_regex_action {context task depth} {
	upvar $context ctx

	set match_str [dict get $task CMD_STR]
	append_jlog "\n>>>>>> REGEX:[first_100 $match_str]"

	set match_str [var_substitution $ctx $match_str]	

	return [process_match_action ctx $task $depth $match_str]
}


proc execute_expr_action {context task depth} {
	upvar $context ctx

	set cmd_str [dict get $task CMD_STR]
	append_jlog "\n>>>>>> EXPR:[first_100 $cmd_str]"

	set str [var_substitution $ctx $cmd_str]
	set value [expr $str]
	
	return [process_match_action ctx $task $depth $value]
}


proc execute_eval_action {context task depth} {
	upvar $context ctx

	set cmd_str [dict get $task CMD_STR]
	append_jlog "\n>>>>>> EVAL:[first_100 $cmd_str]"

	set str [var_substitution $ctx $cmd_str]
	set value [eval $str]
	
	return [process_match_action ctx $task $depth $value]
}


proc process_match_action {context task depth match_str} {
	upvar $context ctx

	set opt_dict [dict get $task OPTIONS]
	
	# Replace \n \r with the actual special charater
	if {[dict exists $opt_dict L]} {
		set match_str [regsub -all {\\n} $match_str "\n"]
		set match_str [regsub -all {\\r} $match_str "\r"]
	}
	
	# process task-level catch group
	foreach cgrp_dict [dict get $task CGROUPS] {
		process_cgroup ctx $cgrp_dict $match_str
	}
	
	if {![dict exists $task XLIST]} {
		return 0
	}
	
	set xlist [dict get $task XLIST]	
	
	for {set i 0} {$i < [llength $xlist]} {incr i} {
		set x [lindex $xlist $i]
		set exp [dict get $x EXP]	
		set opt [dict get $x OPTIONS]
		set cgrp_list [dict get $x CGROUPS]
		
		if {[dict exists $opt L]} {
			# use the -inline -all options in regexp to return a flat list of all the matches
			#
			set matched_list [eval {regexp -inline -all $exp $match_str}]
			
			set n [llength $matched_list]
			set m [llength $cgrp_list]
			
			for {set i 0} {$i < $n} {incr i [expr $m+1]} {
				append_jlog "\nFound match <$exp>"
			
				process_mgroup_list ctx $cgrp_list [lrange $matched_list [expr $i+1] [expr $i+$m]]

				set r [execute_task_list ctx [dict get $x TASK_LIST] [expr $depth+1]]
				if {$r != 0} {
					return $r
				} 
			}
			
			if {$n > 0} {
				return [dict get $x XCODE] 
			}
		} else {
			# construct the regexp command string with all the catch groups defined
			#
			set eval_str {regexp $exp $match_str match_all}
			for {set j 1} {$j <= [llength $cgrp_list]} {incr j} {
				set eval_str "$eval_str mv($j)"
			}
				
			# initialize array variable mv. 
			# This variable will be instantiated in the "eval" function call
			array set mv {}

			if {[eval $eval_str]} {
				append_jlog "Found match <$exp>"
				
				# make a list from all the values in the array
				set mlist [list]
				foreach {index value} [array get mv] {
					lappend mlist $value
				}
				
				process_mgroup_list ctx $cgrp_list $mlist
				
				set r [execute_task_list ctx [dict get $x TASK_LIST] [expr $depth+1]]
				if {$r != 0} {
					return $r
				} 
				return [dict get $x XCODE] 
			}
		}
	}
	
	if {[dict exists $task XOTHER]} {
		append_jlog "No match found. Entering XOTHER"
		set x [dict get $task XOTHER]
		set tlist [dict get $x TASK_LIST]
		set r [execute_task_list ctx $tlist [expr $depth+1]]
		if {$r != 0} {
			return $r
		} 
		return [dict get $x XCODE]	
	} 
	
	return 0
}


# Process capture groups
#
proc process_cgroup_list {context cgrp_list} {
	upvar $context ctx
	global expect_out g_run_mode
	
	
	foreach cgrp_dict $cgrp_list {
		set i [dict get $cgrp_dict i]
		if {![info exists expect_out($i,string)]} {
			append_jlog "catpture group $i is not defined!"
			exit -1
		}
		
		set buf [dict get $ctx MORE_BUFFER]
		set buf "$buf$expect_out($i,string)"
		
		process_cgroup ctx $cgrp_dict $buf		
	}
}


# Process match groups
#
proc process_mgroup_list {context cgrp_list mlist} {
	upvar $context ctx
	
		
	foreach cgrp_dict $cgrp_list {
		set i [dict get $cgrp_dict i]
		if {$i > [llength $mlist]} {
			append_jlog "\ncatpture group $i is not defined!"
			exit -1
		}
		
		process_cgroup ctx $cgrp_dict [lindex $mlist [expr $i-1]]
	}
}


proc process_cgroup {context grp_dict value} {
	upvar $context ctx
	global g_run_mode
	
	foreach k [dict keys $grp_dict] {
		if {$k eq "W" || $k eq "A"} {
			set file [dict get $grp_dict $k]			
			if {[string length $file] == 0} {
				append_jlog "<$k> File name is not defined!"
				exit -1
			}
			set file [var_substitution $ctx $file]
											
			if {$k eq "W"} {
				if {[string equal -nocase $g_run_mode MULTI]} {
					set dev_ip [dict get $ctx VARIABLES DEV_IP]
					set file "${dev_ip}__${file}"
				}

				append_jlog "Write content to file '$file'"

				set f [open $file w]
				puts $f $value
				close $f				
			} else {
				append_jlog "Append content to file '$file'"

				set f [get_fd $file]
				puts $f $value
			}
		} elseif {$k eq "V"} {
			set v [dict get $grp_dict V]
			dict set ctx VARIABLES $v $value
			append_jlog "Set variable $v to <[first_100 $value]>"
		}
	}
}


proc first_100 {s} {
	if {[string length $s] <= 100} {
		return $s
	} else {
		return "[string range $s 0 100] ......more text omitted"
	}
}


proc get_fd {file} {
	global gd_fd
	
	if {![dict exists $gd_fd $file]} {
		dict set gd_fd $file [open $file w]
	}
	
	return [dict get $gd_fd $file]
}


proc options_to_string {o} {
	set s {}
	
	if {[dict exists $o R]} {
		set s "$s -regexp"
	}
	# Add more options here if defined...
	
	return $s
}


proc execute_call_action {context task depth} {
	upvar $context ctx
	global NULL_VALUE gd_proc_lib
	
	set proc_name [dict get $task PROCNAME]
	append_jlog "\n>>>>>> CALL $proc_name......"
	
	# Use runtime argument if supplied, otherwise
	# use default argument is defined, othersise
	# raise an error
	#
	set runtime_args [dict get $task ARGUMENTS]
	set defined_args [dict get $gd_proc_lib $proc_name ARGUMENTS]
	dict for {arg_name arg_value} $defined_args {
		if {[dict exists $runtime_args $arg_name]} {
			set runtime_val [dict get $runtime_args $arg_name]
			dict set defined_args $arg_name [var_substitution $ctx $runtime_val]
		} else {
			if {[dict get $defined_args $arg_name] eq $NULL_VALUE} {
				append_jlog "Missing value for argument $arg_name!!!"
				exit -1
			}
		}
	}

	# append the arg list to the context
	set stack [dict get $ctx CALL_STACK]
	lappend stack $defined_args
	dict set ctx CALL_STACK $stack
	
	set task_list [dict get $gd_proc_lib $proc_name TASKS]
	set ret [execute_task_list ctx $task_list $depth]
	append_jlog "\nFunction $proc_name finished"
	
	return $ret
}


# Perform variable substitution. There are 3 types of variable:
#   1. Variables (including system and user-defined)
#   2. Function arguments
#
proc var_substitution {ctx str} {
	set pwd [pwd]
	set str [regsub -all {\${SYS:PATH_ABS}} $str $pwd]


	# substitute all variables defined in capture group
	#
	while {[regexp {\$\{V:(\w+)\}} $str match_line var]} {
		set r [quotemeta "\$\{V:${var}\}"]
		set v [dict get $ctx VARIABLES $var]
		set vv [fix_regsub $v]
		set str [regsub $r $str $vv]
	}
	
	# substitute input arguments
	#
	set call_stack [dict get $ctx CALL_STACK]
	set proc_args [lindex $call_stack end]

	while {[regexp {\$\{A:(\w+)\}} $str match_line var]} {
			set r [quotemeta "\$\{A:${var}\}"]
			set v [dict get $proc_args $var]
			set vv [fix_regsub $v]
			set str [regsub $r $str $vv]
	}
	
	return $str
}


# Escape all non-word characters in the string (by prepending an extra '\' character)
# 
proc quotemeta {str} {
    set str [regsub -all -- {\W} $str {\\&}]
    return $str
}


# Double escape these TROUBLESOME characters: & and \
#
proc fix_regsub {s} {
	set s1 [list]
	set len [string length $s]
	for {set i 0} {$i < $len} {incr i} {
		set c [string index $s $i]
		if {$c eq "\&" || $c eq "\\"} {
			lappend s1 "\\"
		}
		lappend s1 $c
	}
	return [join $s1 ""]
}


# A job is consisted of a list of tasks. 
#
# A task is consisted of:
#    - CONNECT/SEND/EXEC/PUSH/COLLECT/CALL/SET/REGEX/EXPR/EVAL statement
#    - one or more XPECT statements
#    - an optional XOTHER statement (expect timeout/eof)
#    - an optional XERROR statement (connection failure)
#    - XPECT/XOTHER/XERROR must be terminated by an XEND statement
#
# Each XPECT contains the following:
#    - an expression to be matched
#    - a task list (may be empty)
#    - an XEND 
#
# 'EXPECT' keyword is a shorthand denotation for XPECT/XEND pair which has an empty task list
# 'COLLECT' keyword is a shorthand denotation for SEND followed by an {R|W}EXPECT:(.*)${DEV_PROMPT}
#
#  job (task_list)
#  |
#  +--task (multiple)
#  |  |
#  |  +--action: CONNECT/DISCONNECT/SEND/EXEC/PUSH/COLLECT/CALL/REGEX/EXPR/EVAL
#  |  |
#  |  +-- XPECT (multiple)
#  |  |   |
#  |  |   +-- task_list
#  |  |   |
#  |  |   +--XEND:(NEXT/PASS/FAIL/LOOP)
#  |  |   
#  |  +-- XPECT
#  |  |   |
#  |  |   +--...
#  |  |
#  |  +--XOTHER (optional)
#  |  |  |
#  |  |  +-- task_list
#  |  |  |
#  |  |  +--XEND:(NEXT/PASS/FAIL/LOOP)
#  |  |
#  |  +--XERROR (optional)
#  |     |
#  |     +-- task_list
#  |     |
#  |     +--XEND:(NEXT/PASS/FAIL/LOOP)
#  |
#  +--task
#  |
#  +--... 
#  
# A task ends when one of the two conditions is met:
#   1. End of the file has been reached. This is the main task
#   2. A "XEND" statement has been reached. This is a sub-task.
#
# From a parsing perspective, XEND statement is ALWAYS consumed by read_task_list
#
# RETURN VALUE:
#   NEXT (0)	-- Continue 
#   PASS (1)	-- Exit with success
#   FAIL (-1)	-- Exit with failure
#   LOOP (2)	-- Recheck (exp_continue)
#
proc read_task_list {buffer_dict} {		
	upvar $buffer_dict buf_dic
	
	set task_list [list]
	
	while {1} {
		# If end of file is reached, return an empty list
		if {[script_buffer_retrieve_next_line buf_dic line] < 0} {
			set ret 0
			break
		}

		# IMPORTANT!!! Put the line back to the buffer to be handled by read_task 
		#
		return_line_to_script_buffer buf_dic $line

		# If XEND is encountered, it means an empty sub-task list
		if {[regexp {^\s*XEND(?:\:(.*))?$} $line]} {
			set ret 0
			break
		}
		
		ljoin task_list [read_task buf_dic]
	}
	
	return $task_list
}


# A task is consisted of:
#    1. A SEND statement
#    2. One or more XPECT clause
#    3. An optional XTO clause
#    4. An optional XEOF clause
# The XPECT/XTO/XEOF clause must end with an XEND statement
# The XPECT/XTO/XEOF clause may contain a task list
# Parsing the task list **consumes** the XEND statement
proc read_task {buffer_dict} {		
	upvar $buffer_dict buf_dic
	global timeout

	if {[script_buffer_retrieve_next_line buf_dic line] < 0} {
		return [list]
	}
	
	# process DISCONNECT action
	#
	if {[regexp {^\s*DISCONNECT\s*$} $line]} {
		set task [dict create ACTION DISCONNECT]
		return [list $task] 
	} 
	
	if {![regexp {^\s*(?:\[(.*?)\])?(.*)(CONNECT|SEND|EXEC|PUSH|COLLECT|CALL|REGEX|EXPR|EVAL):(.*)$} $line match_line options cgroups action cmd_str]} {	
		send_user "\nInvalid command $line. [buffer_info buf_dic]"
		exit -1
	}

	set cmd_str [string trim $cmd_str]
	set options [string trim $options]
	set t_opt_dict [parse_task_options buf_dic $options $timeout]
	set t_grp_list [parse_cgroups buf_dic $cgroups]
	
	# process CALL action
	if {$action eq "CALL"} {
		if {![regexp {\s*(\w+)\s?(.*)} $cmd_str mline proc_name arg_str]} {
			append_jlog "Missing proc_name: $cmd_str. [buffer_info buf_dic]"
			exit -1
		}
		
		set call_args [parse_proc_call_args buf_dic $arg_str]
		set task [dict create ACTION $action CMD_STR $cmd_str OPTIONS $t_opt_dict PROCNAME $proc_name ARGUMENTS $call_args]
		return [list $task]
	} 
	
	# process COLLECT action
	#
	if {$action eq "COLLECT"} {
		# COLLECT is a shorthand for:
		#     SEND:command string
		#     [R]<W>EXPECT:(.*)${V:DEV_PROMPT}
		# COLLECT command can carry a capture group which contains the name of the output file
		set xopt [dict create R 1]
		
		# default action is to write to a file named after the command string
		if {[string length $cgroups] == 0} {
			set cgroups "<W:$cmd_str>"
		}
		set cgrp_list [parse_cgroups buf_dic $cgroups]
		
		set x [dict create EXP {(.*)${V:DEV_PROMPT}} OPTIONS $xopt CGROUPS $cgrp_list TASK_LIST [list] XCODE 0]
		
		set task [dict create ACTION SEND CMD_STR $cmd_str XLIST [list $x] OPTIONS $t_opt_dict]
		return [list $task]
	} 
	
	# Start process actions that may carry an XPECT/EXPECT clause
	#
	set cmd_list [list]

	# Translate the PUSH command into a list of SEND commands
	#
	if {$action eq "PUSH"} {
		if {$cmd_str ne "BEGIN"} {
			send_user "\nExpecting 'BEGIN' after PUSH. [buffer_info buf_dic]\n"
			exit -1
		}	
		
		set action SEND

		while {1} {
			if {[script_buffer_retrieve_next_line buf_dic line] <= 0} {
				send_user "\nMissing PUSH:END. [buffer_info buf_dic]"
				exit -1
			}
			if {[regexp {^\s*PUSH:END$} $line]} {
				break
			}
			lappend cmd_list [string trim $line]
		}		
	} elseif {$action eq "CONNECT" || $action eq "SEND" || $action eq "EXEC" || $action eq "REGEX" || $action eq "EXPR" || $action eq "EVAL"} {
		lappend cmd_list $cmd_str
	} else {
		send_user "\nInvalid command $action encountered. [buffer_info buf_dic]"
		exit -1
	}
	
	# process the XPECT/EXPECT/XOTHER/XERROR clauses
	#
	while {1} {
		if {[script_buffer_retrieve_next_line buf_dic line] < 0} {
			break
		}

		if {[regexp {^\s*(?:\[(.*?)\])?(.*)EXPECT:(.*)$} $line match_line options cgroups expression]} {
			if {[info exists xlist] > 0} {
				send_user "\nEXPECT command must not mix with other clauses. [buffer_info buf_dic]"
				exit -1
			}
			
			# EXPECT is a shorthand for XEPCT clause with an empty sub-task list
			set opt_dict [parse_xpect_options buf_dic $options]		
			set cgrp_list [parse_cgroups buf_dic $cgroups]
			lappend xlist [dict create EXP $expression OPTIONS $opt_dict CGROUPS $cgrp_list TASK_LIST [dict create] XCODE 0]
			break
		} elseif {[regexp {^\s*(?:\[(.*?)\])?XOTHER(?:\:(.*?))?$} $line match_line options other_args]} {
			if {[info exists xother] > 0} {
				send_user "\nOnly 1 XOTHER clauses is allowed. [buffer_info buf_dic]"
				exit -1
			}
			
			set opt_dict [parse_xpect_options buf_dic $options]
			set tlist [read_task_list buf_dic]
			set xcode [read_xend buf_dic]
			mark_exp_continue tlist $xcode
			set xother [dict create OPTIONS $opt_dict TASK_LIST $tlist XCODE $xcode]
			break
		} elseif {[regexp {^\s*(?:\[(.*?)\])?XERROR(?:\:(.*?))?$} $line match_line options err_args]} {
			if {[info exists xerror] > 0} {
				send_user "\nOnly 1 XERROR clause is allowed. [buffer_info buf_dic]"
				exit -1
			}
			
			set opt_dict [parse_xpect_options buf_dic $options]
			set tlist [read_task_list buf_dic]
			set xcode [read_xend buf_dic]
			mark_exp_continue tlist $xcode
			set xerror [dict create OPTIONS $opt_dict TASK_LIST $tlist XCODE $xcode]
			break
		} elseif {[regexp {^\s*(?:\[(.*?)\])?(.*)XPECT:(.*)$} $line match_line options cgroups expression]} {
			set opt_dict [parse_xpect_options buf_dic $options]
			set cgrp_list [parse_cgroups buf_dic $cgroups]
			set tlist [read_task_list buf_dic]
			set xcode [read_xend buf_dic]
			mark_exp_continue tlist $xcode
			lappend xlist [dict create EXP $expression OPTIONS $opt_dict CGROUPS $cgrp_list TASK_LIST $tlist XCODE $xcode]
		} else {
			return_line_to_script_buffer buf_dic $line
			break
		}
	}
	
	set tasklist [list]
	
	foreach cmd $cmd_list {
		set task [dict create ACTION $action CMD_STR $cmd]
		
		dict set task OPTIONS $t_opt_dict
		dict set task CGROUPS $t_grp_list
		
		if {$action eq "CONNECT"} {
			dict set task ARGUMENTS [parse_connect_arguments buf_dic $cmd_str]
		}
		
		if {[info exists xlist]} {
			dict set task XLIST $xlist
		}
		
		if {[info exists xother]} {
			dict set task XOTHER $xother
		}
		
		if {[info exists xerror]} {
			dict set task XERROR $xerror
		}
		
		lappend tasklist $task
	}
	
	return $tasklist
}


proc read_xend {buffer_dict} {
	upvar $buffer_dict buf_dic
	
	# If end of file is reached, return an empty list		
	if {[script_buffer_retrieve_next_line buf_dic line] < 0} {
		send_user "\nExpecting XEND. [buffer_info buf_dic]"
		exit -1
	}

	if {[regexp {^\s*XEND(?:\:(.*))?$} $line match_all action]} {
		if {[string length $action] == 0 || $action eq "NEXT"} {
			set xcode 0
		} elseif {$action eq "PASS"} {
			set xcode 1
		} elseif {$action eq "LOOP"} {
			set xcode 2
		} elseif {$action eq "FAIL"} {
			set xcode -1
		} else {
			send_user "\nInvalid xcode $action in. [buffer_info buf_dic]"
			exit -1
		}
	}
	
	return $xcode
}


proc mark_exp_continue {task_list xcode} {
	upvar $task_list tlist
	
	if {$xcode == 2} {
		set t [lindex $tlist end]
		dict set t LOOP 1
		lset tlist end $t
	}
}

proc buffer_info {buffer_dict} {
	upvar $buffer_dict buf_dic
	set buf_name [dict get $buf_dic NAME]
	set line_no [expr [dict get $buf_dic READ_INDEX]+1]
	return "Script Name=$buf_name, Line #=$line_no"
}


proc parse_task_options {buffer_dict opt_str timeout} {
	upvar $buffer_dict buf_dic
	set read_index [dict get $buf_dic READ_INDEX]
	
	set opt_dict [dict create]
	set opt_list [split [string trim $opt_str] "|"]

	foreach opt $opt_list {
		if {[regexp {T:(\d+)} $opt match to]} {
			dict set opt_dict T $to
		} elseif {[regexp {L} $opt]} {
			dict set opt_dict L 1
		} else {
			send_user "\nInvalid option: $opt. [buffer_info buf_dic]"
			exit -1
		}
	}	
	if {![dict exists $opt_dict T]} {
		dict set opt_dict T $timeout
	}
	
	return $opt_dict
}


proc parse_xpect_options {buffer_dict opt_str} {
	upvar $buffer_dict buf_dic
	set read_index [dict get $buf_dic READ_INDEX]

	set opt_dict [dict create]
	set opt_list [split $opt_str "|"]

	foreach opt $opt_list {
		if {[regexp {R} $opt]} {
			dict set opt_dict R 1
		} elseif {[regexp {L} $opt]} {
			dict set opt_dict L 1
		} elseif {[regexp {N:(\d+)} $opt match n]} {
			dict set opt_dict N $n
		} else {
			send_user "\nInvalid option: $opt. [buffer_info buf_dic]"
			exit -1
		}
	}	
	return $opt_dict
}


proc parse_connect_arguments {buffer_dict arg_str} {
	upvar $buffer_dict buf_dic
	set read_index [dict get $buf_dic READ_INDEX]

	set conn_args [dict create]
	set arg_list [split [string trim $arg_str] " "]
	foreach pair $arg_list {
		if {[regexp {([A-Z_]+)=(.*)} $pair match name value]} {
			dict set conn_args $name $value
		} else {
			send_user "\nInvalid argument $pair encountered. [buffer_info buf_dic]"
			exit -1
		}
	}
	
	return $conn_args
}


proc parse_cgroups {buffer_dict cgrp_str} {
	upvar $buffer_dict buf_dic
	set read_index [dict get $buf_dic READ_INDEX]

	set i 1
	set grp_dict_list [list]
	
	foreach GRP [regexp -inline -all -- {<.*?>} $cgrp_str] {	
		regexp {<(.*)>} $GRP whole grp
		foreach g [split $grp "|"] {	
			set g_dict [dict create i $i]

			if {[regexp {W\:(.+)} $g match file]} {
				dict set g_dict W $file
			} elseif {[regexp {A\:(.+)} $g match file]} {
				dict set g_dict A $file
			} elseif {[regexp {V\:(\w+)} $g match var]} {
				dict set g_dict V $var
			} else {
				send_user "\nInvalid catch group: $g. [buffer_info buf_dic]"
				exit -1
			}
				
			lappend grp_dict_list $g_dict
		}
		incr i
	}
	
	return $grp_dict_list
}


proc parse_proc_def_args {buffer_dict arg_str} {
	upvar $buffer_dict buf_dic
	global NULL_VALUE
	
	set d [dict create]
	
	while 1 {
		set arg_str [string trim $arg_str]
		if {$arg_str eq ""} {
			break
		}
		
		if {[regexp {^\s*(\w+)\s*=(.*)} $arg_str line arg_name rest]} {
			set arg_val [parse_arg_val buf_dic rest]
			dict set d $arg_name $arg_val
			set arg_str $rest
		} elseif {[regexp {^\s*(\w+)(.*)} $arg_str line arg_name rest]} {
			dict set d $arg_name $NULL_VALUE
			set arg_str $rest
		} else {
			puts "parse_proc_def_args: Invalid argument list $arg_str. [buffer_info buf_dic]"
			exit -1			
		}
	}
	
	return $d
}


proc parse_proc_call_args {buffer_dict arg_str} {
	upvar $buffer_dict buf_dic
	global NULL_VALUE

	set d [dict create]
	
	while 1 {
		set arg_str [string trim $arg_str]
		if {$arg_str eq ""} {
			break
		}

		if {[regexp {\s*(\w+)\s*=(.*)} $arg_str match_line arg_name rest]} {
			set arg_val [parse_arg_val buf_dic rest]
			dict set d $arg_name $arg_val
			set arg_str $rest
		} else {
			puts "parse_proc_call_args: Invalid argument list $arg_str. [buffer_info buf_dic]"
			exit -1
		} 
	}
	
	return $d
}


proc parse_arg_val {buffer_dict arg_str} {
	upvar $buffer_dict buf_dic
	upvar $arg_str str
	set read_index [dict get $buf_dic READ_INDEX]
	
	set i 0
	set start 0
	set layer 0
	set len [string length $str]

	while {$i < $len} {
		set ch [string index $str $i]
		
		if {$ch eq "\{"} {
			incr layer
			if {$layer == 1} {
				set start $i
			}
		} elseif {$ch eq "\}"} {
			incr layer -1
			if {$layer < 0} {
				send_user  "\nExpecting '\{'. [buffer_info buf_dic]"
				exit -1
			} elseif {$layer == 0} {
				set ret [string range $str [expr $start+1] [expr $i-1]]
				set str [string range $str [expr $i+1] $len]
				return $ret
			}
		} elseif {$ch eq "\\"} {
			# The next character is to be escaped
			incr i
		} 
		
		incr i
	}
	
	if {$layer == 0} {
		send_user "\nExpecting '\{'. [buffer_info buf_dic]"
	} else {
		send_user "\nExpecting '\}'. [buffer_info buf_dic]"	
	}
	exit -1
}


proc dump_task_list {task_list level} {	
	foreach task $task_list {
		dump_task $task $level
		
		if {$level == 0} {
			puts ""
		}
	}
}


proc dump_task {task level} {
	set indent [string repeat "." [expr $level*4]]	
	set action [dict get $task ACTION]
	
	if {$action eq "DISCONNECT"} {
		puts ${indent}${action}
		return
	} 
	
	set str "$action:[dict get $task CMD_STR]"
	if {[dict exists $task OPTIONS]} {
		set opt_dict [dict get $task OPTIONS]
		set opt_str "\[[opt_dict_to_str $opt_dict]\]"
		set str ${opt_str}${str}
	}
	puts ${indent}${str}
	
	if {[dict exists $task XLIST]} {
		foreach x [dict get $task "XLIST"] {
			set xopt_dict [dict get $x OPTIONS]
			set xopt_str "\[[opt_dict_to_str $xopt_dict]\]"
			set cgrp_list [dict get $x CGROUPS]
			set cgrp_str [cgrp_list_to_str $cgrp_list]
			
			puts ${indent}${xopt_str}${cgrp_str}XPECT:[dict get $x EXP]

			dump_task_list [dict get $x TASK_LIST] [expr $level+1]
			
			set xcode [dict get $x "XCODE"]
			puts ${indent}XEND:[exit_code_to_str $xcode]
		}
	}
	
	if {[dict exists $task XOTHER]} {
		puts ${indent}XOTHER

		set xother [dict get $task XOTHER]
		dump_task_list [dict get $xother TASK_LIST] [expr $level+1]
		
		set xcode [dict get $xother "XCODE"]
		puts ${indent}XEND:[exit_code_to_str $xcode]
	}

	if {[dict exists $task XERROR]} {
		puts ${indent}XERROR

		set xerror [dict get $task XERROR]
		dump_task_list [dict get $xerror TASK_LIST] [expr $level+1]
		
		set xcode [dict get $xerror "XCODE"]
		puts ${indent}XEND:[exit_code_to_str $xcode]
	}
}


proc opt_dict_to_str {opt_dict} {
	set d_list [list]
	dict for {k v} $opt_dict {
		lappend d_list $k:$v
	}
	return [join $d_list "|"]
}


proc cgrp_list_to_str {cgroup_list} {
	set cg_list [list]
	foreach cgrp $cgroup_list {
		lappend cg_list "\<[opt_dict_to_str $cgrp]\>"
	}
	return [join $cg_list]
}


proc exit_code_to_str {xcode} {
	if {$xcode == 0} {
		return "NEXT"
	} elseif {$xcode == 1} {
		return "PASS"
	} elseif {$xcode == 2} {
		return "LOOP"
	} elseif {$xcode == -1} {
		return "FAIL"
	} else {
		send_user "\nInvalid xcode $xcode"
		exit -1
	}
}


proc append_jlog {msg} {
	global jlog
	
	send_user "\n$msg"	
	lappend jlog $msg
}


proc ljoin {list1 list2} {
	upvar $list1 L1
	
	foreach e $list2 {
		lappend L1 $e
	}
	return $L1
}


proc read_dev_file {dev_file} {
	set ip_list [list]
	set infile [open $dev_file r]
	while {[gets $infile line] >= 0} {
		if ![regexp {^\s*(\d+\.\d+\.\d+\.\d+)\s*$} $line match_result ip] {
			continue
		}
		lappend ip_list $ip
	}
	return $ip_list
}


# Read script file into a buffer (list). The reason this is needed is because
# when putting a line back, we must account for line break characters which 
# may include one of \r\n, or both. There is no way to determine which is the
# case.
#
proc script_buffer_init {file} {
	set script_buffer [list]
	set fd [open $file r]
	while {[gets $fd line] >= 0} {
		lappend script_buffer $line
	}
	
	return [dict create NAME $file BUFFER $script_buffer READ_INDEX 0]
}


# Retrieve a line from the script buffer. The following lines are ignored:
#   1. Block comment lines (Lines enclosed by ###)
#   2. Single comment line (Line beginning with a #)
#   3. Blank line
#
proc script_buffer_retrieve_next_line {buffer_dict line_out} {
	upvar $buffer_dict buf_dic
	upvar $line_out line

	set buffer [dict get $buf_dic BUFFER]
	set i [dict get $buf_dic READ_INDEX]
	set blockcomment false
	
	while {$i < [llength $buffer]} {
		set line [lindex $buffer $i]
		incr i
		
		# check for blockcomment tag '###'
		if {[regexp {^###$} $line]} {
			set blockcomment [expr {!$blockcomment}]
			continue
		}
		
		# ignore blockcomment'ed lines
		if {$blockcomment} {
			continue
		}
		
		# remove leading and trailing whitespaces
		set line [string trim $line]

		# ignore empty line
		if {$line eq ""} {
			continue
		}
	
		# ignore comment line
		if ([regexp {^#} $line]) {
			continue
		}
		
		dict set buf_dic READ_INDEX $i
		return [string length $line]
	}
	
	return -1
}


proc return_line_to_script_buffer {buffer_dict line} {
	upvar $buffer_dict buf_dic

	set i [dict get $buf_dic READ_INDEX]
	dict set buf_dic READ_INDEX [expr $i-1]
}


# proc_dict:
#
# proc1
#    |
#    +----ARG_LIST
#    |
#    +----TASK_LIST
#       
# proc2
#    |
#    +----ARG_LIST
#    |
#    +----TASK_LIST
#          
# ...
#
proc parse_lib_file {lib_file} {
	set lib_dict [dict create]
	
	set fd [open $lib_file r]
	while {[gets $fd line] >= 0} {
		set line [string trim $line]
		if {$line eq "" || [regexp {^#} $line]} {
			continue
		}
		
		if {[regexp {^PROCDEF:\s*(\w+)\s?(.*)} $line match_line proc_name args_str]} {
			set lib_buffer [list]
			set complete 0
			
			while {[gets $fd line] >= 0} {
				set line [string trim $line]

				#if {$line eq "" || [regexp {^#} $line]} {
				#	continue
				#}
				
				if {[regexp {^PROCEND\s*} $line]} {
					set complete 1
					break
				}

				lappend lib_buffer $line
			}	
			
			if {!$complete} {
				append_jlog "Missing PROCEND for $proc_name"
				exit -1
			}
			
			set buffer_dict [dict create NAME "PROC $proc_name" BUFFER $lib_buffer READ_INDEX 0]
			set conn_args [parse_proc_def_args buffer_dict $args_str]
			set task_list [read_task_list buffer_dict]
			dict set lib_dict $proc_name ARGUMENTS $conn_args
			dict set lib_dict $proc_name TASKS $task_list
		} else {
			append_jlog "Expecting PROCDEF in $lib_file"
			exit -1
		}
	}
	
	return $lib_dict
}


proc dump_gd_proc_lib {lib} {	
	dict for {proc_name proc_data} $lib {
		set args [dict get $proc_data ARGUMENTS]
		set tasks [dict get $proc_data TASKS]
		puts "\n\n------------Begin proc definition"
		puts "\n$proc_name: [dict keys $args]"
		dump_task_list $tasks 0
		puts "------------End proc definition"
	}
}


proc init_ctx {ip} {
	global gd_task_ctx
	
	set vars_dict [dict create DEV_IP $ip]
	
	if {[dict exists $gd_task_ctx VARIABLES DEV_PROMPT]} {
		dict set vars_dict DEV_PROMPT [dict get $gd_task_ctx VARIABLES DEV_PROMPT]
	}

	if {[dict exists $gd_task_ctx VARIABLES SPAWN_ID]} {
		dict set vars_dict SPAWN_ID [dict get $gd_task_ctx VARIABLES SPAWN_ID]
	}
		
	return [dict create VARIABLES $vars_dict CALL_STACK [list] MORE_BUFFER {}]
}


if {$argc == 0 || [string equal -nocase [lindex $argv 0] "-h"]} {
	send_user "\nUsage: scriptname -h -p <password-file> -ds <per-device config script> -dvs <> -drs <>"
	exit 0
}


log_file terminal_log	
set gl_all_device_results [list]
set gd_fd [dict create]
set gd_proc_lib [dict create]
set gd_pwd_db [dict create]
set gl_pre_task_list [list]
set gl_post_task_list [list]
set gl_dev_config_task_list [list]
set gl_dev_verify_task_list [list]
set gl_dev_rollback_task_list [list]
set gl_ip_list [list]
set g_run_mode SINGLE
set gd_task_ctx [dict create CALL_STACK [list]]

# =========================================================================
# =========================================================================
# Start the job execution
# =========================================================================
# =========================================================================
set start_time [clock milliseconds]

set i 0
while {$i < $argc} {
    set opt [lindex $argv $i]
	
    if {[string equal -nocase $opt {-dcs}]} {
        incr i
		set device_config_script [lindex $argv $i]
		set buffer_dict [script_buffer_init $device_config_script]
		set gl_dev_config_task_list [read_task_list buffer_dict]
		puts "\n\n--------------------Begin per device task list definition\n"
		dump_task_list $gl_dev_config_task_list 0
		puts "--------------------End per device task list definition"
    } elseif {[string equal -nocase $opt {-dvs}]} {
        incr i
		set device_verify_script [lindex $argv $i]
		set buffer_dict [script_buffer_init $device_verify_script]
		set gl_dev_verify_task_list [read_task_list buffer_dict]
		puts "\n\n--------------------Begin per device task list definition\n"
		dump_task_list $gl_dev_verify_task_list 0
		puts "--------------------End per device task list definition"
    } elseif {[string equal -nocase $opt {-drs}]} {
        incr i
		set device_rollback_script [lindex $argv $i]
		set buffer_dict [script_buffer_init $device_rollback_script]
		set gl_dev_rollback_task_list [read_task_list buffer_dict]
		puts "\n\n--------------------Begin per device task list definition\n"
		dump_task_list $gl_dev_rollback_task_list 0
		puts "--------------------End per device task list definition"
    } elseif {[string equal -nocase $opt {-pre}]} {
        incr i
		set pre_script [lindex $argv $i]
		set buffer_dict [script_buffer_init $pre_script]
		set gl_pre_task_list [read_task_list buffer_dict]
		puts "\n\n--------------------Begin PRE task list definition\n"
		dump_task_list $gl_pre_task_list 0
		puts "--------------------End PRE task list definition"
    } elseif {[string equal -nocase $opt {-post}]} {
        incr i
		set post_script [lindex $argv $i]
		set buffer_dict [script_buffer_init $post_script]
		set gl_post_task_list [read_task_list buffer_dict]
		puts "\n\n--------------------Begin POST task list definition\n"
		dump_task_list $gl_post_task_list 0
		puts "--------------------End POST task list definition"
    } elseif {[string equal -nocase $opt {-p}]} {
        incr i
		set pwd_file [lindex $argv $i]
		set gd_pwd_db [read_pwd_db $pwd_file]
		
		puts "\n\n--------------------Begin credential file: $pwd_file\n"
		dict for {rule cred} $gd_pwd_db {
			puts "Rulename: $rule"
			puts "Username: [dict get $cred USERNAME]"
			puts "Password: [dict get $cred PASSWORD]\n"
		}
		puts "--------------------End credential file"
    } elseif {[string equal -nocase $opt {-iplist}]} {
		set arg [lindex $argv [expr $i+1]]
		while {[regexp {\d+\.\d+\.\d+\.\d+} $arg]} {
			lappend gl_ip_list $arg
			incr i
			set arg [lindex $argv [expr $i+1]]
		}
    } elseif {[string equal -nocase $opt {-ipfile}]} {
        incr i
        set dev_file [lindex $argv $i]
		set dev_list [read_dev_file $dev_file]
		set gl_ip_list [concat $gl_ip_list $dev_list]
	} elseif {[string equal -nocase $opt {-L}]} {
        incr i
        set lib_file [lindex $argv $i]
		set gd_proc_lib [parse_lib_file $lib_file]
		dump_gd_proc_lib $gd_proc_lib
	}
	
    incr i
}


if {[llength $gl_ip_list] > 1} {
	set g_run_mode "MULTI"
} else {
	set g_run_mode "SINGLE"
}



#execute PRE task list first
#
if {[llength $gl_pre_task_list] > 0} {
	send_user "\n\n\n\n>>>>>>>>>>>> Processing PRE config script"
	set result [execute_task_list gd_task_ctx $gl_pre_task_list 0]
	if {$result >= 0} {
		append_jlog "\n<<<<<<<<<<<< PRE config job completed successfully"
	} else {
		append_jlog "\n<<<<<<<<<<<< PRE config job failed"
		exit -1
	}
}

# ----------------------------------------------
# Loop through each device......
# ----------------------------------------------
foreach ip $gl_ip_list {	
	set jlog [list]
	set cfg_ctx [init_ctx $ip]

    send_user "\n\n\n\n>>>>>>>>>>>> Processing device $ip"
	
	set cfg_result [execute_task_list cfg_ctx $gl_dev_config_task_list 0]
	if {$cfg_result >= 0} {
		append_jlog "\n<<<<<<<<<<<< Config job completed successfully"

		if {[llength $gl_dev_verify_task_list] > 0} {
			append_jlog "\n>>>>>>>>> Executing verify script"
			set vfy_ctx [init_ctx $ip]
			set vfy_result [execute_task_list vfy_ctx $gl_dev_verify_task_list 0]
			if {$vfy_result < 0} {
				append_jlog "\nVerification job failed"
				
				if {[llength $gl_dev_rollback_task_list] > 0} {
					append_jlog "\n>>>>>>>>> Executing rollback script"
					set roll_result [execute_task_list cfg_ctx $gl_dev_rollback_task_list 0]
					if {$roll_result < 0} {
						append_jlog "\n>>>>>>>>> Rollback job failed"
					} else {
						append_jlog "\n>>>>>>>>> Rollback job completed successfully"
					}
				}
			} else {
				append_jlog "\n>>>>>>>>> Verification job completed successfully"
			}
		}
	} else {
		append_jlog "\n<<<<<<<<<<<< Config job failed"
	}
	
	lappend gl_all_device_results [dict create IP $ip RESULT $cfg_result CTX $cfg_ctx JLOG $jlog]
}

#execute POST task list first
#
if {[llength $gl_post_task_list] > 0} {
	send_user "\n\n\n\n>>>>>>>>>>>> Processing POST config script"
		dump_task_list $gl_post_task_list 0
	set result [execute_task_list gd_task_ctx $gl_post_task_list 0]
	if {$result >= 0} {
		append_jlog "\n<<<<<<<<<<<< POST config job completed successfully"
	} else {
		append_jlog "\n<<<<<<<<<<<< POST config job failed"
		exit -1
	}
}

send_user "\n\n"

send_user "\nCreating job_results.csv......"
set outfile [open "job_results.csv" w]

puts $outfile "IP,Result"
foreach entry $gl_all_device_results {
	set ip [dict get $entry IP]
	set result [dict get $entry RESULT]
	if {$result >= 0} {
		puts $outfile "$ip,Success"
	} else {
		puts $outfile "$ip,Fail"
	}
}
close $outfile

send_user "\nCreating job_log.txt......"
set outfile [open "job_log.txt" w]
foreach entry $gl_all_device_results {
	puts $outfile "---------------------------------"
	puts $outfile "[dict get $entry IP]"
	set ctx [dict get $entry CTX]
	foreach j [dict get $entry JLOG] {
		puts $outfile $j
	}
}
close $outfile

# close all output files
dict for {fname fd} $gd_fd {
	close $fd
}

set end_time [clock milliseconds]
set elapsed [expr ($end_time-$start_time)/1000.0]

send_user "\nAll done!"
send_user "\nTotal run time: [format "%.4f" $elapsed] seconds\n"
log_file
exit 0