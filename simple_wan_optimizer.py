import wan_optimizer
from utils import get_hash
from tcp_packet import Packet
from utils import MAX_PACKET_SIZE
import logging

logging.basicConfig()
LOG = logging.getLogger(name='simple_wan_optimizer')
LOG.setLevel(logging.INFO)

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into fixed-size blocks.

    This WAN optimizer should implement part 1 of project 4.
    """

    # Size of blocks to store, and send only the hash when the block has been
    # sent previously
    BLOCK_SIZE = 8000

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        # Add any code that you like here (but do not add any constructor arguments).
        self.buffer = dict() # <Key, Value> <(src, destination), string of data>
        self.seen = dict() # <Key, Value>: <Hash of a Block, Actual Block>
        return

    def receive(self, packet):
        """ Handles receiving a packet.

        Right now, this function simply forwards packets to clients (if a packet
        is destined to one of the directly connected clients), or otherwise sends
        packets across the WAN. You should change this function to implement the
        functionality described in part 1.  You are welcome to implement private
        helper fuctions that you call here. You should *not* be calling any functions
        or directly accessing any variables in the other middlebox on the other side of 
        the WAN; this WAN optimizer should operate based only on its own local state
        and packets that have been received.
        """
        if packet.dest in self.address_to_port:
            # The packet is destined to one of the clients connected to this middlebox;
            # send the packet there.
            wan_packets = self.handle_packet(packet, client=True)
            if wan_packets:
                for wan_packet in wan_packets:
                    LOG.debug('WAN Packet size {}'.format(wan_packet.size()))
                    self.send(wan_packet, self.address_to_port[packet.dest])
            #self.send(packet, self.address_to_port[packet.dest])
        else:
            # The packet must be destined to a host connected to the other middlebox
            # so send it across the WAN.

            # Implement all code here?
            # But what should the interface be .......

            # Pseudo code first:
            """
            Buffer (i.e. chill with data until we have enough data)
            if it's full send it, but if that's the last then send it.

            Side-concern:
            Hash every block, and save it
            """
            LOG.debug('Received {}'.format(packet.size()))
            wan_packets = self.handle_packet(packet)
            if wan_packets:
                for wan_packet in wan_packets:
                    LOG.debug('WAN Packet size {}'.format(wan_packet.size()))
                    self.send(wan_packet, self.wan_port)
            #self.send(packet, self.wan_port)

    def handle_packet(self, packet, client=False):
        """
        Add the packet to the buffer and return a packet if the block_size is reached

        Args:
            :tcp_packet packet: the packet received by self.receive

        Returns:
        None | list[Packet]

        Notes
        ------
        Receives a packet
        """
        current_flow = (packet.src, packet.dest)
        if packet.is_raw_data:
            data = packet.payload
            more_bytes = packet.size()
        else:
            LOG.debug('Received a payload I have seen before')
            data = self.seen[packet.payload]
            more_bytes = len(data)
        current_buffer_size = len(self.buffer.get(current_flow, []))
        new_length = current_buffer_size + more_bytes
        LOG.debug('Current Buffer: {} vs New Length: {}'.format(current_buffer_size, new_length))
        if new_length >= self.BLOCK_SIZE:
            overflow = new_length - self.BLOCK_SIZE
            LOG.debug('Overflow: {}'.format(overflow))
            tight_fit = more_bytes - overflow
            LOG.debug('Remainder {}'.format(tight_fit))
            # Make sure you're not skipping a byte here cause of careless indexing
            block_of_data = self.buffer.get(current_flow, '') + data[:tight_fit]
            if overflow:
                self.buffer[current_flow] = data[-overflow:] # Put the rest of the bits in buffer
            else:
                self.buffer[current_flow] = ''
            # what if this packet is the fin? with overflow? then, I need to send the buffer later ...
            packets_to_send = []
            packets_to_send.extend(self.send_packet(block_of_data, packet, False, client=client))
            if packet.is_fin:
                # The overflow will be the last packet that is also a fin!
                last_packet = self.send_packet(self.buffer.get(current_flow), packet, True, client=client)
                self.buffer[current_flow] = ''
                packets_to_send.extend(last_packet)
            return packets_to_send
        else:
            # Simply add the packet to the buffer
            self.buffer[current_flow] = self.buffer.get(current_flow, '') + data
            if packet.is_fin:
                LOG.debug('el fin received in sub MAX_PACKET_SIZE: {}'.format(len(self.buffer[current_flow])))
                whats_in_your_buffer = self.buffer[current_flow]
                tosend = self.send_packet(whats_in_your_buffer, packet, True, client=client)
                # Clear buffer now
                self.buffer[current_flow] = ''
                return tosend

    def send_packet(self, block_of_data, packet, is_fin, client=False):
        """
        Turn a block of data into a list of packets to send

        Args:
            :str block_of_data: a self.BLOCK_SIZE amount of data
            :tcp_packet.Packet packet: a Packet
            :boolean is_fin: final packet
            :boolean client: are these packets sent to a client?

        Returns:
        list[tcp_packet.Packet]
        """
        digest = get_hash(block_of_data)
        # Copy src, dest
        if digest in self.seen and not client:
            is_raw_data = False
            assert len(digest) <= MAX_PACKET_SIZE, "Hash is not less than block_size"
            return [Packet(packet.src, packet.dest, is_raw_data, is_fin, digest)]
        else:
            self.seen[digest] = block_of_data
            num_blocks = len(block_of_data) // MAX_PACKET_SIZE
            rest = len(block_of_data) % MAX_PACKET_SIZE
            blocks = [block_of_data[k * MAX_PACKET_SIZE : (k + 1) * MAX_PACKET_SIZE] for k in range(num_blocks)]
            is_raw_data = True
            send = []
            for block in blocks:
                assert len(block) <= MAX_PACKET_SIZE, '{} > {}'.format(len(block), MAX_PACKET_SIZE)
                wan_packet = Packet(packet.src, packet.dest, is_raw_data, False, block)
                send.append(wan_packet)
            assert rest <= MAX_PACKET_SIZE, 'REST is large as af: {}'.format(rest)
            if rest:
                last_packet = Packet(packet.src, packet.dest, is_raw_data, is_fin, block_of_data[-rest:])
                send.append(last_packet)
            else:
                last_packet = Packet(packet.src, packet.dest, is_raw_data, is_fin, '')
                send.append(last_packet)
            return send



