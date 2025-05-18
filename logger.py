import logging
from pathlib import Path
from datetime import datetime
from json import loads, dumps
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
        conn_id: str = f"{src}:{sport} -> {dst}:{dport}" # use it as uniq id

        log_entry = {
            "timestamp": str(datetime.now()),
            "conn_id": conn_id,
            "seq_num": seq_num,
            "payload": payload[:SIZE]  # Truncate for readability
        }

        with open(self.json_log_file, "a") as f:
            f.write(dumps(log_entry) + "\n")

        msg = f"SUSPICIOUS: {conn_id} | Seq: {seq_num}"
        if payload:
            msg += f" | Payload: {payload[:100]}..."
        self.logger.warning(msg)

    def reassemble_from_log(self):
        '''This function used to reassbmle tcp packets'''
        connection_data = {}

        # Read logs and group packets by connection ID
       # import ipdb; ipdb.set_trace()
        with open(self.json_log_file, "r") as f:
            for line in f:
                entry = loads(line)
                conn_id = entry["conn_id"]
                seq_num = entry["seq_num"]
                payload = entry["payload"]

                if conn_id not in connection_data:
                    connection_data[conn_id] = {}

                connection_data[conn_id][seq_num] = payload

        # Reconstruct messages in correct sequence order
        for conn_id, packets in connection_data.items():
            reconstructed_data = "".join(
                packets[seq] for seq in sorted(packets)
            )
            print(f"\n[Reconstructed] {conn_id}")
            print(f"Complete Payload:\n{reconstructed_data}\n")


