import docker
import docker.errors
import os
import json
import logging
import tempfile
import shutil

class ExtractedFile:
    def __init__(self, size: int, success: bool, extractor: str, outputDir: str):
        self.size = size
        self.success = success
        self.extractor = extractor
        self.outputDir = outputDir
        
    def __repr__(self):
        return (f"ExtractedFile(size={self.size}, success={self.success}, "
                f"extractor='{self.extractor}', outputDir='{self.outputDir}')")

class DetectedFile:
    def __init__(self, offset: int, id: str, size: int, confidence: float, description: str, extractionDetails: ExtractedFile | None = None):
        self.offset = offset
        self.id = id
        self.size = size
        self.confidence = confidence
        self.description = description
        self.extractionDetails = extractionDetails
        
    def __repr__(self):
        return (f"DetectedFile(offset={self.offset}, id={self.id}, size={self.size}, "
                f"confidence={self.confidence}, description='{self.description}', "
                f"extractionDetails={self.extractionDetails})")
        

def parseBinwalkLog(logFilePath: str, hostOut: str, guestOut: str) -> list[DetectedFile]:
    if not os.path.isfile(logFilePath):
        raise RuntimeError("Log file 'log.json' not found. Ensure that binwalk ran successfully.")
    with open(logFilePath, 'r') as logFile:
        try:
            logData = json.load(logFile)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse log file: {e}") from e
        
    try:
        logData = logData[0]
        logData = logData['Analysis']
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"Log file format is incorrect or missing expected fields: {e}") from e
    
    extractedFiles = logData.get("extractions", {})
    
    detectedFiles = []
    for file in logData.get("file_map", []):
        try:
            offset = file['offset']
            id = file['id']
            size = file['size']
            confidence = file['confidence']
            description = file['description']
            extractionDetails = None
            
            if id in extractedFiles:
                extractedFile = extractedFiles[id]
                realOutputDir = extractedFile['output_directory'].replace(guestOut, hostOut, 1)
                extractionDetails = ExtractedFile(
                    size=extractedFile['size'],
                    success=extractedFile['success'],
                    extractor=extractedFile['extractor'],
                    outputDir=realOutputDir
                )
            
            detectedFiles.append(DetectedFile(
                offset=offset,
                id=id,
                size=size,
                confidence=confidence,
                description=description,
                extractionDetails=extractionDetails
            ))
        except KeyError as e:
            logging.error(f"Missing expected key in log entry: {e}")
            
    return detectedFiles
    

def checkFile(filePath: str) -> bool:
    """
    
    Check if the file exists and if the user can mount it to the Docker container.
    :param filePath: Path to the file to check.
    :return: True if the file exists and is mountable, False otherwise.

    """
    if not os.path.isfile(filePath):
        logging.error(f"File not found: {filePath}")
        return False
    
    # Get full path of file 
    fullPath = os.path.abspath(filePath)
    # Check that the user has mount permissions on the parent directory 
    parentDir = os.path.dirname(fullPath)
    if not os.access(parentDir, os.W_OK | os.R_OK):
        logging.error(f"User does not have write permissions on the parent directory: {parentDir}")
        return False
    
    return True

def checkOutputDirectory(outputDirectory: str) -> bool:
    """
    Check if the output directory exists and is writable.
    
    :param outputDirectory: Path to the output directory.
    :return: True if the directory exists and is writable, False otherwise.
    """
    if not os.path.isdir(outputDirectory):
        logging.error(f"Output directory does not exist: {outputDirectory}")
        return False
    
    if not os.access(outputDirectory, os.W_OK | os.R_OK):
        logging.error(f"User does not have write permissions on the output directory: {outputDirectory}")
        return False
    
    return True

def generateDockerArgs(
    filePath: str,
    verbose: bool = False,
    extract: bool = False,
    recursive: bool = False,
    searchAll: bool = False,
    excludeSignatures: list[str] = [],
    includeSignatures: list[str] = [],
    outputDirectory: str = "",
) -> tuple[list[str], dict[str, dict[str, str]], str, tuple[str, str]]:
    
    args = []
    volumes = {}
    
    # Get the absolute path of the file
    fullPath = os.path.abspath(filePath)
    inputDir = os.path.dirname(fullPath)
    fileName = os.path.basename(fullPath)

    args.append(os.path.join("/input", fileName))  # File path inside the container

    if verbose:
        args.append("-v")
    if extract:
        args.append("-e")
    if recursive:
        args.append("-r")
    if searchAll:
        args.append("-a")
    if len(excludeSignatures) > 0:
        args.append("--exclude")
        args.extend(excludeSignatures)
    if len(includeSignatures) > 0:
        args.append("--include")
        args.extend(includeSignatures)

    args.extend(["-l", "/analysis/log.json"])  # Log file path inside the container

    # Create a temp directory for the log file
    logDir = tempfile.mkdtemp()
    volumes[logDir] = {'bind': '/analysis', 'mode': 'rw'}
    volumes[inputDir] = {'bind': '/input', 'mode': 'rw'}
    
    # If output is a directory, bind it to the container else create the folder inside the input directory
    if outputDirectory != "":
        outputDir = os.path.abspath(outputDirectory)
        outputDirGuest = "/output"
        volumes[outputDir] = {'bind': '/output', 'mode': 'rw'}
        args.extend(["-C", "/output"])  # Output directory inside the container
    else:
        outputDir = os.path.join(inputDir, "extractions")
        outputDirGuest = "/input/extractions"
        args.extend(["-C", "/input/extractions"])  # Output directory inside the container

    return args, volumes, logDir, (outputDir, outputDirGuest)

def copyLogFile(input: str, output: str):
    """
    Copy the log file from the input path to the output path.
    
    :param input: Path to the input log file.
    :param output: Path to the output log file.
    """
    if not os.path.isfile(input):
        logging.error(f"Log file not found: {input}")
        return
    
    if output:
        try:
            with open(input, 'r') as infile, open(output, 'w') as outfile:
                outfile.write(infile.read())
            logging.info(f"Log file copied to {output}")
        except Exception as e:
            logging.error(f"Failed to copy log file: {e}")
    else:
        logging.warning("No output path provided for log file.")    

def runBinwalk(
    filePath: str,
    verbose: bool = False,
    extract: bool = False,
    recursive: bool = False,
    searchAll: bool = True,
    logFile: str = "",
    excludeSignatures: list[str] = [],
    includeSignatures: list[str] = [],
    outputDirectory: str = "",
):

    if not checkFile(filePath):
        return []

    if outputDirectory != "" and not checkOutputDirectory(outputDirectory):
        return []
    
    args, volumes, logDir, (hostOut, guestOut) = generateDockerArgs(filePath, verbose, extract, recursive, searchAll, excludeSignatures, includeSignatures, outputDirectory)


    client = docker.from_env()
    try:
        result = client.containers.run(
            'binwalkv3',
            args,
            remove=True,
            volumes=volumes,
            working_dir='/input'
        )

    except docker.errors.ContainerError as e:
        raise RuntimeError(f"Binwalk failed: {e}") from e
    except docker.errors.ImageNotFound:
        raise RuntimeError("Docker image 'binwalkv3' not found. Make sure you used the install script first") from None
    except Exception as e:
        raise RuntimeError(f"An unexpected error occurred: {e}") from e

    logFilePath = os.path.join(logDir, 'log.json')
    logData = parseBinwalkLog(logFilePath, hostOut, guestOut)
    
    if logFile:
        copyLogFile(logFilePath, logFile)

    # Clean up the temporary log directory
    try:
        shutil.rmtree(logDir)
    except OSError as e:
        logging.error(f"Failed to remove temporary log directory {logDir}: {e}")

    return logData
