# Copyright 2021 NXP
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

#!/usr/bin/python3
#auto upload file to aws s3
import sys
import os
import subprocess
import argparse
import inotify.adapters
import logging
import boto3
from botocore.exceptions import ClientError

# define a const class
class _const:
    class ConstError(TypeError):pass
    def __setattr__(self,name,value):
        if name in self.__dict__:
            raise self.ConstError("Can't rebind const (%s)" %name)
        self.__dict__[name]=value
const = _const()
const.REGION_NAME = 'us-east-2'

# define 
class _opt:
    def __init__(self):
        self.bucket_name = None
        self.region_name = None
        self.expired_days= 30
        self.watched_dir = '.'
    def __str__(self):
        str='upload to cloud options:\n'
        if self.bucket_name is not None:
            str += 'bucket_name: %s\n' % self.bucket_name
        if self.region_name is not None:
            str += 'region_name: %s\n' % self.region_name
        if self.watched_dir is not None:
            str += 'watched_dir: %s\n' % self.watched_dir
        str += 'expired_days: %d\n' % self.expired_days
        return str

def upload_file(s3_client, bucket, file_name, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = os.path.basename(file_name)

    # Upload the file
    try:
        s3_client.upload_file(file_name, bucket, object_name)
    except ClientError as e:
        logging.error(e)
        return False
    print("Upload %s success\n" % file_name)
    return True

def set_bucket_lifecycle(s3_client, bucket, days):
    response = s3_client.put_bucket_lifecycle_configuration(
        Bucket=bucket,
        LifecycleConfiguration={
            'Rules': [
                {
                    'Expiration': {
                        'Days': days,
                    },
                    'Filter': {},
                    'ID': 'auto del',
                    'Status': 'Enabled'
                }
            ]
        }
    )
    print(response)

def generate_bucket_name_from_mac():
    result = subprocess.run(['ifconfig', 'eth0'], stdout=subprocess.PIPE)
    str = result.stdout.decode('utf-8')
    #print(str)
    str = str.splitlines()[0]
    #print(str)
    str = str.split()[4]
    #print(str)
    str = str.replace(':','-').lower()
    return str

def read_region_name_from_aws_config():
    with open("/home/%s/.aws/config" % os.environ['USER'], "r") as f:
        lines = f.readlines()
        for line in lines:
            if 'region' in line:
                return line.split()[2]
    return None

def init_bucket(s3_client, opts):
    if opts.bucket_name is None:
        opts.bucket_name = generate_bucket_name_from_mac()
        print("Use MAC address %s as bucket name\n" % opts.bucket_name)

    if opts.region_name is None:
        opts.region_name = read_region_name_from_aws_config()
        if opts.region_name is None:
            opts.region_name = const.REGION_NAME
    
    try:
        response = s3_client.create_bucket(
            Bucket = opts.bucket_name,
            CreateBucketConfiguration = {
                'LocationConstraint': opts.region_name,
            },
        )
    except s3_client.exceptions.BucketAlreadyExists:
        pass
    except s3_client.exceptions.BucketAlreadyOwnedByYou:
        pass
    except Exception as e:
        print(e)
        return False
    else:
        print("New create bucket: %s\n" % opts.bucket_name)
        print(response)
    
    set_bucket_lifecycle(s3_client, opts.bucket_name, opts.expired_days)
    return True

def upload_main(opts):
    # init opts from argv

    s3_client = boto3.client('s3')
    if init_bucket(s3_client, opts) is False:
        return

    print("watched path: %s\n" % opts.watched_dir)
    
    i = inotify.adapters.Inotify()
    i.add_watch(opts.watched_dir, inotify.constants.IN_CLOSE_WRITE)
    print("Start watch...\n")
    for event in i.event_gen(yield_nones=False):
        #print(event)
        file = "%s/%s" %(event[2], event[3])
        print("upload %s to cloudl" % file)        
        upload_file(s3_client, opts.bucket_name, file)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Watched specified directory and auto upload to S3')
    parser.add_argument('-r', '--region', help="Specify the region name of AWS")
    parser.add_argument('-b', '--bucket', help="Specify the bucket name")
    parser.add_argument('-d', '--expired-days', type=int, default=30, help="Specify expired days for files in bucket")
    parser.add_argument('dir', help="Specify the directory needed to be uploaded to AWS")
    args = parser.parse_args()
    print(args)
    opts = _opt()
    opts.bucket_name = args.bucket
    opts.region_name = args.region
    opts.expired_days = args.expired_days
    opts.watched_dir = args.dir
    print(opts)
    upload_main(opts)