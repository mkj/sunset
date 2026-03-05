# merge-logs.sh
# Useful to get events from both client and server logs in chronological order.
#
# usage: ./merge-logs.sh client.log server.log > merged.log
CLIENT_LOG=$1
SERVER_LOG=$2
{
  awk 'match($0,/^\[([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z)\]/,m){print m[1] "\tC:\t" $0}' "$CLIENT_LOG"
  awk 'match($0,/^\[([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z)/,m){print m[1] "\tS:\t" $0}' "$SERVER_LOG"
} | sort -t $'\t' -k1,1 | cut -f2-