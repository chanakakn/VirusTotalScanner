#!/usr/bin/env python3

import argparse
import glob
import hashlib
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import openpyxl
from pynput import keyboard
from virus_total_apis import PublicApi as VirusTotalPublicApi

# Constants
VT_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
FILE_PATH = r"C:\Users\Desktop\tt"
ALERTING_LEVEL = int(0.1)
IS_RECURSIVE = True
LOG_FILE = "script.log"
EXCEL_FILE = "results.xlsx"

# VirusTotal API initialization
vt_api = VirusTotalPublicApi(VT_KEY)


class SimpleFile:
    def calculate_hash(self, file_name):
        sha256_hash = hashlib.sha256()
        with open(file_name, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def __init__(self, file_name):
        self.file_name = file_name
        self.hash = self.calculate_hash(file_name)

    def get_hash(self):
        return self.hash

    def get_file_name(self):
        return self.file_name


class ObservedEntity:
    def __init__(self, file, alerting_level):
        self.files = []
        self.files.append(file.get_file_name())
        self.hash = file.get_hash()
        self.isMalicious = False
        self.vt_result = ''
        self.positives = 0
        self.total_scanners = 1
        self.ALERTING_LEVEL = alerting_level

    def add_file_name(self, file_name):
        self.files.append(file_name)

    def get_file_names(self):
        return self.files

    def get_hash(self):
        return self.hash

    def add_virustotal_result(self, result):
        self.vt_result = result
        json_data = json.loads(json.dumps(result))
        try:
            if json_data['results']['response_code'] == 1:
                self.total_scanners = json_data['results']['total']
                self.positives = json_data['results']['positives']
                self.scan_date = json_data['results']['scan_date']
        except KeyError:
            logging.error("Received unexpected response from VirusTotal:")
            logging.error(result)
            sys.exit("\nReceived invalid response from VirusTotal. Did you enter a valid VT API Key?")

    def get_virustotal_result(self):
        return self.vt_result

    def is_malicious(self):
        return self.count_alerting_scanners() / self.count_total_scanners() >= self.ALERTING_LEVEL

    def count_total_scanners(self):
        return self.total_scanners

    def count_alerting_scanners(self):
        return self.positives


class EntityHandler:
    def __init__(self):
        self.hash_dict = {}

    def add_file(self, file, alerting_level):
        new_file = SimpleFile(file)
        existing_duplicates = self.hash_dict.get(new_file.get_hash())
        if existing_duplicates is not None:
            existing_duplicates.add_file_name(new_file.get_file_name())
        else:
            self.hash_dict.update({new_file.get_hash(): ObservedEntity(new_file, alerting_level)})

    def get_entities(self):
        return self.hash_dict.items()

    def count_entities(self):
        return len(self.hash_dict)


def vt_scan_file(file_hash):
    try:
        result = vt_api.get_file_report(file_hash)
        return result
    except Exception as e:
        logging.error(f"Error occurred while scanning file {file_hash}: {e}")
        return None


def process_file(file, alerting_level):
    file_hash = SimpleFile(file).get_hash()
    vt_result = vt_scan_file(file_hash)
    if vt_result:
        observed_entity = ObservedEntity(SimpleFile(file), alerting_level)
        observed_entity.add_virustotal_result(vt_result)
        return observed_entity
    return None


def process_files(file_path, alerting_level, is_recursive):
    entity_handler = EntityHandler()

    with ThreadPoolExecutor() as executor:
        futures = []
        for file in glob.iglob(file_path + '/**/*', recursive=is_recursive):
            if os.path.isfile(file):
                future = executor.submit(process_file, file, alerting_level)
                futures.append(future)

        for future in as_completed(futures):
            observed_entity = future.result()
            if observed_entity:
                entity_handler.add_file(observed_entity.get_file_names()[0], alerting_level)
                entity_handler.get_entities()[observed_entity.get_hash()] = observed_entity

    return entity_handler


def export_results_to_excel(entity_handler):
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "Results"
    sheet.append(["Hash", "Files", "Total Scanners", "Positive Scanners", "Scan Date"])

    for _, observed_entity in entity_handler.get_entities():
        if observed_entity.is_malicious():
            file_names = observed_entity.get_file_names()
            hash_value = observed_entity.get_hash()
            total_scanners = observed_entity.count_total_scanners()
            positive_scanners = observed_entity.count_alerting_scanners()
            scan_date = observed_entity.scan_date

            sheet.append([hash_value, ", ".join(file_names), total_scanners, positive_scanners, scan_date])

    workbook.save(EXCEL_FILE)


def main():
    # Set up logging
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    # Parse command-line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path", default=FILE_PATH, help="Search path")
    parser.add_argument("-a", "--alertlv", default=ALERTING_LEVEL, type=float, help="Alerting level")
    parser.add_argument("-r", "--recursive", metavar="recursive", default=IS_RECURSIVE, choices=['True', 'False'], help="Include subfolders")
    parser.add_argument("-x", "--excel", default=EXCEL_FILE, help="Excel file path")
    args = parser.parse_args()

    FILE_PATH = args.path
    ALERTING_LEVEL = args.alertlv
    IS_RECURSIVE = args.recursive
    EXCEL_FILE = args.excel

    logging.info(f"Working with the following parameters:\nSearch path: {FILE_PATH}\nInclude subfolders: {IS_RECURSIVE}\nAlerting level: {ALERTING_LEVEL}")

    try:
        entity_handler = process_files(FILE_PATH, ALERTING_LEVEL, IS_RECURSIVE)
        export_results_to_excel(entity_handler)
        logging.info(f"Finished processing {entity_handler.count_entities()} files.")
    except Exception as e:
        logging.error(f"An error occurred during file processing: {e}")


if __name__ == '__main__':
    main()
