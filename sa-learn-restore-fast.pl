#!/usr/bin/perl -w

use strict;
use warnings;
use DBI;

# $Id: sa-learn-restore-fast.pl,v 1.2 2021/11/09 23:14:03 poc Exp $

# How to access the databases.
# FIXME: Get this information from the spamassassin configuration file.
our $odbc_dsn      = "DBI:ODBC:Driver={iSeries Access ODBC Driver};System=Nibbler;DBQ=SPAMASSASS";
our $odbc_user     = "myspamassassinuser";
our $odbc_password = "myspamassassinpassword";

# Database-Handles
our ($odbc_dbh, $sth_v1, $sth_v1_u, $sth_v2, $sth_t, $sth_s, $sth_tmp);

# Database field names (for the four main tables being used).
our ($variable, $value,
	$id, $username, $token_count, $last_expire, $last_atime_delta, $last_expire_reduce,
	$oldest_token_age, $newest_token_age, $token, $spam_count, $ham_count, $atime,
	$msgid, $flag);

# Runtime variables
our ($line, $count, $token_hex, $token_ham_count, $token_spam_count);

#--------------------------------------------------------------------------------------------------------------

$odbc_dbh = DBI->connect($odbc_dsn, $odbc_user, $odbc_password, {PrintError => 1});
if ( ! $odbc_dbh ) {
	my $dbhError="Error: Connect failed:\n";
	if (defined($DBI::err))    { $dbhError=$dbhError . $DBI::err . "\n"; }
	if (defined($DBI::errstr)) { $dbhError=$dbhError . $DBI::errstr . "\n"; }
	if (defined($DBI::state))  { $dbhError=$dbhError . $DBI::state; }
	printf("%s\n");
	die;
}


# Prepare SQL statements we will need.
$sth_v1 = $odbc_dbh->prepare(
	"INSERT INTO bayes_global_vars (value, variable) VALUES (?, ?)"
);
if ( ! defined($sth_v1) ) {
	printf(<STDERR>, "Prepare_v1: Error: '%s'\n", $odbc_dbh->errstr);
    die;
}

$sth_v1_u = $odbc_dbh->prepare(
	"UPDATE bayes_global_vars SET value=? WHERE variable=?"
);
if ( ! defined($sth_v1_u) ) {
	printf(<STDERR>, "Prepare_v1_u: Error: '%s'\n", $odbc_dbh->errstr);
    die;
}

$sth_v2 = $odbc_dbh->prepare(
	"INSERT INTO bayes_vars (id, username, spam_count, ham_count, token_count, last_expire, last_atime_delta,
							last_expire_reduce, oldest_token_age, newest_token_age)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
);
if ( ! defined($sth_v2) ) {
	printf(<STDERR>, "Prepare_v2: Error: '%s'\n", $odbc_dbh->errstr);
    die;
}

$sth_t = $odbc_dbh->prepare(
	"INSERT INTO bayes_token (id, token, spam_count, ham_count, atime)
				VALUES (?, ?, ?, ?, ?)"
);
if ( ! defined($sth_t) ) {
	printf(<STDERR>, "Prepare_t: Error: '%s'\n", $odbc_dbh->errstr);
    die;
}

$sth_s = $odbc_dbh->prepare(
	"INSERT INTO bayes_seen (id, msgid, flag)
				VALUES (?, ?, ?)"
);
if ( ! defined($sth_s) ) {
	printf(<STDERR>, "Prepare_s: Error: '%s'\n", $odbc_dbh->errstr);
    die;
}


# Calculate new user id for bayes_vars on the fly, or use 1 as default.
$sth_tmp = $odbc_dbh->prepare("SELECT COUNT(*) FROM bayes_vars");
if ( ! defined($sth_tmp) ) {
	printf(<STDERR>, "Prepare_tmp: Error: '%s'\n", $odbc_dbh->errstr);
	die;
}
$sth_tmp->execute();
if ( defined($odbc_dbh->errstr()) ) {
	printf(<STDERR>, "Execute_tmp: Error: '%s'\n", $odbc_dbh->errstr);
	die;
}
($count) = $sth_tmp->fetchrow();
$sth_tmp->finish;

# Act depending on what we've found.
if ($count gt 0) {
	$sth_tmp = $odbc_dbh->prepare("SELECT max(id) + 1 FROM bayes_vars");
	if ( ! defined($sth_tmp) ) {
		printf(<STDERR>, "Prepare_tmp: Error: '%s'\n", $odbc_dbh->errstr);
		die;
	}
	$sth_tmp->execute();
	if ( defined($odbc_dbh->errstr()) ) {
		printf(<STDERR>, "Execute_tmp: Error: '%s'\n", $odbc_dbh->errstr);
		die;
	}
	($id) = $sth_tmp->fetchrow();
	$sth_tmp->finish;
} else {
	$id = 1;
}

# Get current username.
$username = $ENV{'LOGNAME'};
if ( ! defined($username) ) {
	$username = "spamassassin";
}

printf("Using username %s and id %d.\n", $username, $id);


# Read Bayes-Backup file from stdin, format one line and spit it out again.
foreach $line ( <STDIN> ) {
	chomp($line); 

	# Handle t-line. This is where the most work is to be done.
	if ( $line =~ /^t[[:space:]]+([[:digit:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:xdigit:]]{10})$/ ) {
		if ( defined ($1) && defined($2) && defined ($3) && defined($4) ) {
			$token_spam_count = $1;
			$token_ham_count = $2;
			$atime = $3;
			$token_hex = $4;

			# Convert from hex to Char. Output is garbage, but saves space.
			$token = $token_hex;
			($token) =~ s/([a-fA-F0-9]{2}) ?/chr(hex $1)/eg;

			$sth_t->execute($id, $token, $token_spam_count, $token_ham_count, $atime);
			if ( defined($odbc_dbh->errstr()) ) {
				printf(<STDERR>, "Execute_t: Error: '%s'\n", $odbc_dbh->errstr);
				printf(<STDERR>, "Arguments: id=%d, token='%s', spam_count=%d, ham_count=%d, atime=%d\n",
					$id, $token_hex, $token_spam_count, $token_ham_count, $atime);
				die;
			}
		} else {
			printf(<STDERR>, "Handle_t_line: Error: Line matched but at least one value missing.\n");
			die;
		}

		# No need to check the other regex's, just read the next line.
		next;

	# Handle s-line. This is where the second most work is to be done.
	} elsif ( $line =~ /^s[[:space:]]+([hs])[[:space:]]+([[:print:]]+)$/ ) {
		if ( defined ($1) && defined($2) ) {
			$flag = $1;
			$msgid = $2;

			$sth_s->execute($id, $msgid, $flag);
			if ( defined($odbc_dbh->errstr()) ) {
				printf(<STDERR>, "Execute_s: Error: '%s'\n", $odbc_dbh->errstr);
				die;
			}
		} else {
			printf(<STDERR>, "Handle_s_line: Error: Line matched but at least one value missing.\n");
			die;
		}

		# No need to check the other regex's, just read the next line.
		next;

	# Handle v-Line, type 1.
	} elsif ( $line =~ /^v[[:space:]]+([[:digit:]]+)[[:space:]]+db_version$/ ) {
		if ( defined($1) ) {
			# FIXME: Doesn't work? More tests necessary!
			$variable = "VERSION";
			$value = $1;

			# How many VERSION entries do we have?
			$sth_tmp = $odbc_dbh->prepare("SELECT COUNT(*) FROM bayes_global_vars WHERE variable = '" . $variable . "'");
			if ( ! defined($sth_tmp) ) {
				printf(<STDERR>, "Prepare_tmp1: Error: '%s'\n", $odbc_dbh->errstr);
				die;
			}
			$sth_tmp->execute();
			if ( defined($odbc_dbh->errstr()) ) {
				printf(<STDERR>, "Execute_tmp1: Error: '%s'\n", $odbc_dbh->errstr);
				die;
			}
			($count) = $sth_tmp->fetchrow();
			$sth_tmp->finish;

			# Act depending on what we've found.
			if ($count eq 0) {
				$sth_v1->execute($value, $variable);
				if ( defined($odbc_dbh->errstr()) ) {
					printf(<STDERR>, "Execute_v1: Error: '%s'\n", $odbc_dbh->errstr);
					die;
				}
			} elsif ($count eq 1) {
				$sth_v1_u->execute($value, $variable);
				if ( defined($odbc_dbh->errstr()) ) {
					printf(<STDERR>, "Execute_v1_u: Error: '%s'\n", $odbc_dbh->errstr);
					die;
				}
			} else {
				printf(<STDERR>, "Handle_v1_line: Warning: More than one VERSION line found in bayes_global_vars.\n");
			}
		} else {
			printf(<STDERR>, "Regex_v1_line: Error: Line matched but at least one value missing.\n");
			die;
		}

		# No need to check the other regex's, just read the next line.
		next;

	# Handle v-Line, type 2.
	} elsif ( $line =~ /^v[[:space:]]+([[:digit:]]+)[[:space:]]+(num_spam|num_nonspam)$/ ) {
		# Save these values for later.
		if ( defined ($1) && defined($2) ) {
			if ( $2 eq "num_spam" ) {
				$spam_count = $1;
			} elsif ( $2 eq "num_nonspam" ) {
				$ham_count = $1;
			}
		} else {
			printf(<STDERR>, "Handle_v2_line: Error: Line matched but at least one value missing.\n");
			die;
		}

		# No need to check the other regex's, just read the next line.
		next;
	}
}


# Calculate values from current data for insertion into bayes_vars.
$sth_tmp = $odbc_dbh->prepare("SELECT min(atime), max(atime), count(*) FROM bayes_token");
if ( ! defined($sth_tmp) ) {
	printf(<STDERR>, "Prepare_tmp2: Error: '%s'\n", $odbc_dbh->errstr);
	die;
}
$sth_tmp->execute();
if ( defined($odbc_dbh->errstr()) ) {
	printf(<STDERR>, "Execute_tmp2: Error: '%s'\n", $odbc_dbh->errstr);
	die;
}
($oldest_token_age, $newest_token_age, $token_count) = $sth_tmp->fetchrow();
$sth_tmp->finish;

# Fill other variables with defaults.
$last_expire = $last_atime_delta = $last_expire_reduce = 0;

# Write bayes_vars.
$sth_v2->execute($id, $username, $spam_count, $ham_count, $token_count, $last_expire,
		$last_atime_delta, $last_expire_reduce, $oldest_token_age, $newest_token_age);
if ( defined($odbc_dbh->errstr()) ) {
	printf(<STDERR>, "Execute_v2: Error: '%s'\n", $odbc_dbh->errstr);
	die;
}


# Clean up after ourselves.
if ( defined($sth_v1) ) {
	$sth_v1->finish;
}
if ( defined($sth_v1_u) ) {
	$sth_v1_u->finish;
}
if ( defined($sth_v2) ) {
	$sth_v2->finish;
}
if ( defined($sth_t) ) {
	$sth_t->finish;
}
if ( defined($sth_s) ) {
	$sth_s->finish;
}

# Close DB connection.
if ( defined($odbc_dbh) ) {
	$odbc_dbh->disconnect;
}

#--------------------------------------------------------------------------------------------------------------
# vim:tabstop=4:shiftwidth=4:autoindent
# -EOF-
