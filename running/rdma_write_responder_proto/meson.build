#
# Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

project('DOCA_SAMPLE', 'C', 'CPP',
	# Get version number from file.
	version: run_command(find_program('cat'),
		files('/opt/mellanox/doca/applications/VERSION'), check: true).stdout().strip(),
	license: 'Proprietary',
	default_options: ['buildtype=debug'],
	meson_version: '>= 0.61.2'
)

SAMPLE_NAME = 'rdma_write_responder'

# Comment this line to restore warnings of experimental DOCA features
add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: ['c', 'cpp'])

sample_dependencies = []
# Required for all DOCA programs
sample_dependencies += dependency('doca-common')
# The DOCA library of the sample itself
sample_dependencies += dependency('doca-rdma')
# Utility DOCA library for executables
sample_dependencies += dependency('doca-argp')
# [新增] OpenSSL 依赖，用于 TXLKS 协议
sample_dependencies += dependency('openssl')

# [新增] 定义 TXLKS 协议源码目录
# 请根据你的实际目录结构修改此路径。
# 假设 txlks_proto 文件夹位于 samples/doca_rdma/txlks_proto (即当前目录的上两级目录下的 txlks_proto)
txlks_dir = 'txlks_proto'

sample_srcs = [
	# The sample itself
	SAMPLE_NAME + '_sample.c',
	# Main function for the sample's executable
	SAMPLE_NAME + '_main.c',
	# [修改] 使用包含 TCP 和参数解析功能的 protocol 文件
	'../rdma_protocol.c',
	# Common code for all DOCA samples (DOCA 的 common)
	'../../common.c',
    
    # [新增] TXLKS 协议源文件
    # 注意：TXLKS 也有一个 common.c，Meson 会通过路径区分它们，
    # 但请确保 txlks_proto/server.c 中的 main 函数已被删除。
    join_paths(txlks_dir, 'server.c'),
    join_paths(txlks_dir, 'txlks_common.c'),
    join_paths(txlks_dir, 'txlks.c'),
    join_paths(txlks_dir, 'tinymt32.c'),
    join_paths(txlks_dir, 'xsadd.c'),
]

sample_inc_dirs  = []
# Common DOCA library logic
sample_inc_dirs += include_directories('..')
# Common DOCA logic (samples)
sample_inc_dirs += include_directories('../..')
# Common DOCA logic
sample_inc_dirs += include_directories('../../..')
# Common DOCA logic (applications)
sample_inc_dirs += include_directories('../../../applications/common/')
# [新增] TXLKS 头文件路径
sample_inc_dirs += include_directories(txlks_dir)

executable('doca_' + SAMPLE_NAME, sample_srcs,
	c_args : '-Wno-missing-braces',
	dependencies : sample_dependencies,
	include_directories: sample_inc_dirs,
	install: false)