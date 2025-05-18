import logging
from pathlib import Path
from datetime import datetime
from json import loads, dumps
from collections import defaultdict
from hashlib import md5

SAVE_NAME = 'canary_alerts'
SIZE: int = 500


class CanaryLogger:
    def __init__(self, log_file:str = f"{SAVE_NAME}.log", json_log_file:str= f"{SAVE_NAME}.json"):
        logging.basicConfig(
            filename=log_file,
            format='%(asctime)s - %(message)s',
            level=logging.WARNING,
        )
        self.logger = logging.getLogger("CanaryDetector")
        self.json_log_file:str = json_log_file

    def log_alert(self, src, sport, dst, dport, seq_num,payload=""):
        """Log suspicious connection with key details"""
        conn_id: str = f"{src}:{sport}-{dst}:{dport}" # use it as uniq id

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "conn_id": conn_id,
            "seq_num": seq_num,
            "payload": payload[:SIZE] if payload else ''
        }

        with open(self.json_log_file, "a") as f:
            f.write(dumps(log_entry) + "\n")

        msg = f"SUSPICIOUS: {conn_id} | Seq: {seq_num}"

        if payload:
            msg += f" | Payload: {payload[:SIZE]}..."
        self.logger.warning(msg)

    def reassemble_from_log(self):
        '''This function used to reassbmle tcp packets'''
        connection_data = defaultdict(dict)
        stream_stats = defaultdict(lambda: {"count": 0, "first_seen": None, "last_seen": None})
       # import ipdb; ipdb.set_trace()
        with open(self.json_log_file, "r") as f:
            for line in f:
                try:
                    entry = loads(line.strip())
                    conn_id = entry["conn_id"]
                    seq_num = entry["seq_num"]
                    payload = entry.get("payload", "")
                    timestamp = entry.get("timestamp", "")

                    connection_data[conn_id][seq_num] = payload

                    # Update stream statistics
                    if stream_stats[conn_id]["first_seen"] is None:
                        stream_stats[conn_id]["first_seen"] = timestamp
                    stream_stats[conn_id]["last_seen"] = timestamp
                    stream_stats[conn_id]["count"] += 1
                except (KeyError, ValueError) as e:
                    print(f"Error in line {line_num}: {e}")
                    continue

            # Save to file instead of printing
            self.save_reassembled_streams(connection_data, stream_stats)

            # Optional: Print summary
            print(f"\nReassembled {len(connection_data)} connections")
            for conn_id in connection_data:
                print(f"- {conn_id}: {stream_stats[conn_id]['count']} packets")


    def save_reassembled_streams(self, connection_data: dict, stream_stats: dict,
                                 output_file: str = "reassembled_streams.log"):
        """Save reassembled streams to a file with full details"""
        try:
            with open(output_file, "w", encoding='utf-8') as out_file:
                for conn_id, packets in connection_data.items():
                    try:
                        reconstructed = "".join(packets[seq] for seq in sorted(packets))
                        stats = stream_stats[conn_id]

                        report = {
                            "connection_id": conn_id,
                            "timeline": {
                                "first_seen": stats["first_seen"],
                                "last_seen": stats["last_seen"]
                            },
                            "packet_count": stats["count"],
                            "total_size": len(reconstructed),
                            "md5_hash": md5(reconstructed.encode()).hexdigest(),
                            "payload_preview": reconstructed[:SIZE],
                            "full_payload_truncated": len(reconstructed) > SIZE
                        }

                        out_file.write(dumps(report, indent=2) + "\n\n")

                    except Exception as e:
                        error_msg = f"Error processing {conn_id}: {e}"
                        out_file.write(error_msg + "\n\n")
                        print(error_msg)

            print(f"Successfully saved reassembled streams to {output_file}")

        except IOError as e:
            print(f"Failed to write reassembled streams: {e}")