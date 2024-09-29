from scapy.all import *
from dataset_common import read_5hp_list
from dataset_common import string_to_hex_array

import argparse
import json
import numpy as np
import pandas as pd
import os
import pickle
import time
from torch.multiprocessing import Process
from pathlib import Path
import torch
import torch.backends.cudnn as cudnn
from torchvision import transforms
from tqdm import tqdmimport mmap
import struct

import util.lr_decay as lrd
import util.misc as misc
from util.misc import NativeScalerWithGradNormCount as NativeScaler
from util.misc import count_parameters

from PIL import Image

import models_net_mamba

SHM_PATH = "share_memory.dat"
SHM_SIZE = 2 * 1024 * 1024 * 1024
SHM_HEADER_SIZE = 24

def get_args_parser():
    parser = argparse.ArgumentParser('NetMamba settings', add_help=False)
    # 64
    parser.add_argument('--batch_size', default=64, type=int,
                        help='Batch size per GPU (effective batch size is batch_size * accum_iter * # gpus')
    parser.add_argument('--accum_iter', default=1, type=int,
                        help='Accumulate gradient iterations (for increasing the effective batch size under memory constraints)')

    # Model parameters
    parser.add_argument('--model', default='net_mamba_classifier', type=str, metavar='MODEL',
                        help='Name of model to train')

    parser.add_argument('--input_size', default=40, type=int,
                        help='images input size')

    parser.add_argument('--drop_path', type=float, default=0.1, metavar='PCT',
                        help='Drop path rate (default: 0.1)')

    # Optimizer parameters
    parser.add_argument('--clip_grad', type=float, default=None, metavar='NORM',
                        help='Clip gradient norm (default: None, no clipping)')
    parser.add_argument('--weight_decay', type=float, default=0.05,
                        help='weight decay (default: 0.05)')

    parser.add_argument('--lr', type=float, default=None, metavar='LR',
                        help='learning rate (absolute lr)')
    parser.add_argument('--blr', type=float, default=2e-3, metavar='LR',
                        help='base learning rate: absolute_lr = base_lr * total_batch_size / 256')
    parser.add_argument('--layer_decay', type=float, default=0.75,
                        help='layer-wise lr decay from ELECTRA/BEiT')

    # * Mixup params
    parser.add_argument('--checkpoint', default='././output/pretrain/checkpoint.pth',
                        help='checkpoint')
    parser.add_argument('--nb_classes', default=7, type=int,
                        help='number of the classification types')
    parser.add_argument('--device', default='cuda',
                        help='device to use for training / testing')
    parser.add_argument('--seed', default=0, type=int)
    parser.add_argument('--resume', default='',
                        help='resume from checkpoint')

    parser.add_argument('--num_workers', default=10, type=int)
    parser.add_argument('--pin_mem', action='store_true',
                        help='Pin CPU memory in DataLoader for more efficient (sometimes) transfer to GPU.')
                        
    # distributed training parameters
    parser.add_argument('--world_size', default=1, type=int,
                        help='number of distributed processes')
    parser.add_argument('--local_rank', default=-1, type=int)
    parser.add_argument('--dist_on_itp', action='store_true')
    parser.add_argument('--dist_url', default='env://',
                        help='url used to set up distributed training')

    return parser

@torch.no_grad()
def evaluate(images, model, device, if_stat=False):
    mean = [0.5]
    std = [0.5]

    transform = transforms.Compose([
        transforms.Grayscale(num_output_channels=1),
        transforms.ToTensor(),
        transforms.Normalize(mean, std),
    ])

    images = [transform(image) for image in images]

    # for batch in metric_logger.log_every(data_loader, 10, header):
    images_tensor = torch.tensor([])
    for image in images:
        images_tensor = torch.cat((images_tensor, image.view(1, 1, 40, 40)), dim = 0)
    images_tensor = images_tensor.half().to(device, non_blocking = True)

    # compute output
    with torch.cuda.amp.autocast():
        output = model(images_tensor)

    _, pred = output.topk(1, 1, True, True)
    pred = pred.t()

    return pred

def load_model(args):
    misc.init_distributed_mode(args)

    print('job dir: {}'.format(os.path.dirname(os.path.realpath(__file__))))
    print("{}".format(args).replace(', ', ',\n'))

    device = torch.device(args.device)

    # fix the seed for reproducibility
    seed = args.seed + misc.get_rank()
    torch.manual_seed(seed)
    np.random.seed(seed)

    cudnn.benchmark = True

    print(models_net_mamba.__dict__)

    model = models_net_mamba.__dict__[args.model](
        num_classes=args.nb_classes,
        drop_path_rate=args.drop_path,
    )

    checkpoint = torch.load(args.checkpoint, map_location='cpu')
    print("Load checkpoint from: %s" % args.checkpoint)
    checkpoint_model = checkpoint['model']

    #load checkpoint
    msg = model.load_state_dict(checkpoint_model, strict=False)
    print(msg)

    model.to(device)

    return model

def packet_callback(packet, images, names, stream_num, model, device):
    # print(packet.show())
    if packet.type == 2054 or packet.type == 34525:
        return
    name = f"{packet[IP].src}:{packet.sport}_{packet[IP].dst}:{packet.dport}_{packet.proto}"
    wrpcap(f"./pcap/{name}.pcap", packet, append=True)
    stream_num.setdefault(name, 0)
    stream_num[name] += 1
    if stream_num[name] == 5:
        image_filename = f"./pcap/{name}.png"
        res = read_5hp_list(f"./pcap/{name}.pcap")[0]
        flow_array = res.pop("data")
        image = Image.fromarray(flow_array.reshape(40, 40).astype(np.uint8))
        # image.save(image_filename)
        images.append(image)
        names.append(name)
        if len(names) == 16:
            res = evaluate(images, model, device)
            print(res)
            images.clear()
            names.clear()

if __name__ == '__main__':
    args = get_args_parser()
    args = args.parse_args()
    model = load_model(args)

    # switch to evaluation mode
    model.eval()

    device = args.device

	while not os.path.exists(SHM_PATH):
		print(f"Waiting for shared memory file {SHM_PATH} to appear...")
		time.sleep(1)

	with open(SHM_PATH, "r+b") as f:
		mm = mmap.mmap(f.fileno(), SHM_SIZE, access=mmap.ACCESS_WRITE)

		def read_from_queue():
			mm.seek(0)
			read_index, write_index, buffer_size = struct.unpack('QQQ', mm[:SHM_HEADER_SIZE])
			if read_index != write_index:
				print(read_index, write_index)
				
				pkt_len_offset = SHM_HEADER_SIZE + read_index
				pkt_len, = struct.unpack_from('Q', mm, pkt_len_offset)
				pkt_data_offset = (read_index + 8) % buffer_size + SHM_HEADER_SIZE
				
				read_index = (read_index + 8 + pkt_len) % buffer_size

				if (read_index + 8 + pkt_len) >= buffer_size:
					pkt_data = mm[pkt_data_offset: buffer_size + SHM_HEADER_SIZE] + mm[SHM_HEADER_SIZE: read_index + SHM_HEADER_SIZE]
				else:
					pkt_data = mm[pkt_data_offset: pkt_data_offset + pkt_len] # 有点问题？
				
				# read_index = (read_index + 8 + pkt_len) % buffer_size
				header_data = struct.pack('QQQ', read_index, write_index, buffer_size)
				mm.write(header_data)
				
				return pkt_data

			# print(read_index, write_index, buffer_size)
			return None

		images = []

		while True:
			packet_data = read_from_queue()
			if packet_data:
				print(f"Packet received, length: {len(packet_data)} bytes")
				image = Image.fromarray(packet_data.reshape(40, 40).astype(np.uint8))
				images.append(image)
				if len(images) == 16:
					res = evaluate(images, model, device)
					print(res)
			

    # stream_num = {}
    # os.makedirs('./pcap', exist_ok=True)
    # conf.bufsize=104857600
    # images = []
    # names = []
    # sniff(prn=lambda x: packet_callback(x, images, names, stream_num, model, device), store=False, count=10000)
	