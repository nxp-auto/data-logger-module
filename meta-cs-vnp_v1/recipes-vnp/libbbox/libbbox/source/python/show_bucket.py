# Copyright 2021 NXP
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

#!/usr/bin/python3
import sys
import boto3
#import json

def show_bucket():
    s3 = boto3.resource('s3')
    for bucket in s3.buckets.all():
        print(bucket.name)

def show_bucket_files(s3, bucket_name):
    if bucket_name is None:
        print("Please specify a bucket:\n")
        show_bucket()
        return
    
    response = s3.list_objects(
        Bucket = bucket_name,
    )
    #obj = json.loads(response)
    for x in response['Contents']:
        print(x['Key'])
    #print(response)

def _main(argv):
    print('boto3 version is ' + boto3.__version__)
    s3 = boto3.client("s3")
    if len(argv) > 0:
        bucket = argv[0]
    else:
        bucket = None
    show_bucket_files(s3, bucket)

if __name__ == "__main__":
    _main(sys.argv[1:])