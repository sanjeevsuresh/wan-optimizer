import wan_optimizer
import utils
from tcp_packet import Packet
import logging

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into variable-sized
    blocks based on the contents of the file.

    This WAN optimizer should implement part 2 of project 4.
    """

    # The string of bits to compare the lower order 13 bits of hash to
    GLOBAL_MATCH_BITSTRING = '0111011001010'

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        # Add any code that you like here (but do not add any constructor arguments).
        self.buffer = dict() # <Key, Value> <(src, destination), string of data>
        self.seen = dict() # <Key, Value>: <Hash of a Block, Actual Block>
        self.window_size = 48
        return

    def receive(self, packet):
        """ Handles receiving a packet.

        Right now, this function simply forwards packets to clients (if a packet
        is destined to one of the directly connected clients), or otherwise sends
        packets across the WAN. You should change this function to implement the
        functionality described in part 2.  You are welcome to implement private
        helper fuctions that you call here. You should *not* be calling any functions
        or directly accessing any variables in the other middlebox on the other side of
        the WAN; this WAN optimizer should operate based only on its own local state
        and packets that have been received.
        """
        if packet.dest in self.address_to_port:
            # The packet is destined to one of the clients connected to this middlebox;
            # send the packet there.
            self.handle_incoming(packet)
        else:
            # The packet must be destined to a host connected to the other middlebox
            # so send it across the WAN.
            self.handle_outgoing(packet)

    def handle_incoming(self, packet):
        """ Handles an incoming packet.

        Responsibility of this method is to add any raw data to the seen list and translate any
        hashed data. It then forwards the data to the client.
        """
        curr_flow = (packet.src, packet.dest)

        if packet.payload in self.seen:
            packet.payload = self.seen[packet.payload]
            self.send(packet, self.address_to_port[packet.dest])
        elif packet.is_raw_data:
            h_data = utils.get_hash(packet.payload)
            self.seen[h_data] = packet.payload
            self.send(packet, self.address_to_port[packet.dest])
        else:
            LOG.debug('GOT A HASH WE HAVE NEVER SEEN!')


    def handle_outgoing(self, packet):
        """ Handles receiving an outgoing packet.

        This function will deal with an outgoing packet in the manner described by the
        low bandwidth filesystem paper. Namely it will break the file into chunks based off of
        the SHA-1 hash of the data being sent.

        Pseudocode:
        1.) Place received data into a buffer for the (source,dest) pair
        2.) when a fin packet is received:
            a.) compute hash of data
            b.) break hashed data at delimiters of `GLOBAL_MATCH_BITSTRING`
            c.) for each chunk of data:
                i. if the chunk has been cached before send the hash of the chunk
                ii. otherwise send the raw data with the raw_data flag as true
        """
        curr_flow = (packet.src, packet.dest)
        if not curr_flow in self.buffer:
            self.buffer[curr_flow] = list()
        self.buffer[curr_flow].append(packet.payload)
        print "".join(self.buffer[curr_flow])

        if packet.is_fin:
            chunked = self.chunk_data("".join(self.buffer[curr_flow]))
            packets = list()
            for chunk in chunked:
                send_packet = Packet(packet.src, packet.dest, chunk in self.seen.keys, False, chunk)
                packets.append(send_packet)
            packets[-1].is_fin = True
            for send_packet in packets:
                self.send(send_packet, self.wan_port)
            self.buffer[curr_flow] = list()

    def chunk_data(self, data):
        """ Breaks up data based on LBFS method.

        This function will implement the breaking of the data in the fashion described in the LBFS
        paper. Actually implements the sliding window approach to breaking data based off a
        delimiter.

        Arguments:
            data: a string that contains data.
        Returns:
            ordered list of data that should be sent packet by packet. This is a mix of hashed and
            un-hashed data. Data that has been sent or seen before is hashed, other data is sent raw
        Side-effects:
            adds in the <hashed data, raw data> pair to the seen dict.
        """
        num_windows = len(data) - self.window_size
        chunk_start = 0
        chunk_list = []
        offset = 0

        while offset < num_windows:
            window = data[offset : offset + self.window_size] if len(data) > offset + self.window_size else data[offset:]
            hashed = utils.get_hash(window)
            low13 = utils.get_last_n_bits(hashed, 13)

            if low13 == self.GLOBAL_MATCH_BITSTRING:
                # This is where data should be broken up
                chunk = data[chunk_start : offset + self.window_size]
                h_chunk = utils.get_hash(chunk)
                if not h_chunk in self.seen:
                    self.seen[h_chunk] = chunk
                    chunk_list.append(chunk)
                else:
                    chunk_list.append(h_chunk)
                chunk_start = offset + self.window_size + 1
                offset = chunk_start + self.window_size
                continue

            elif len(window) < self.window_size:
                # last packet to send
                chunk = data[chunk_start:]
                h_chunk = utils.get_hash(chunk)
                if not h_chunk in self.seen:
                    self.seen[h_chunk] = chunk
                    chunk_list.append(chunk)
                else:
                    chunk_list.append(h_chunk)
                break

            offset += 1

        return chunk_list
