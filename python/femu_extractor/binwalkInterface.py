import os
import logging
from femu_extractor._lib import run_binwalk as rust_run_binwalk

# Re-export classes for backward compatibility
__all__ = ['DetectedFile', 'ExtractedFile', 'runBinwalk', 'checkFile', 'checkOutputDirectory']

logger = logging.getLogger(__name__)

class ExtractedFile:
    """Details about the extraction of a detected file"""
    def __init__(self, size: int, success: bool, extractor: str, outputDir: str):
        self.size = size
        self.success = success
        self.extractor = extractor
        self.outputDir = outputDir
        
    def __repr__(self):
        return (f"ExtractedFile(size={self.size}, success={self.success}, "
                f"extractor='{self.extractor}', outputDir='{self.outputDir}')")


class DetectedFile:
    """A file that was detected by binwalk during analysis"""
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

        

def checkFile(filePath: str) -> bool:
    """
    Check if the file exists and is readable.
    
    :param filePath: Path to the file to check.
    :return: True if the file exists and is readable, False otherwise.
    """
    if not os.path.isfile(filePath):
        logger.error(f"File not found: {filePath}")
        return False
    
    # Get full path of file 
    fullPath = os.path.abspath(filePath)
    # Check that the user has read permissions on the file
    if not os.access(fullPath, os.R_OK):
        logger.error(f"User does not have read permissions on file: {fullPath}")
        return False
    
    return True


def checkOutputDirectory(outputDirectory: str) -> bool:
    """
    Check if the output directory exists and is writable.
    
    :param outputDirectory: Path to the output directory.
    :return: True if the directory exists and is writable, False otherwise.
    """
    if not os.path.isdir(outputDirectory):
        logger.error(f"Output directory does not exist: {outputDirectory}")
        return False
    
    if not os.access(outputDirectory, os.W_OK):
        logger.error(f"User does not have write permissions on the output directory: {outputDirectory}")
        return False
    
    return True


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
) -> list[DetectedFile]:
    """
    Run binwalk analysis on a firmware file using the native Rust binwalk library.
    
    :param filePath: Path to the firmware file to analyze
    :param verbose: Enable verbose output
    :param extract: Extract detected files
    :param recursive: Recursively extract archives
    :param searchAll: Search for all signatures (default: True)
    :param logFile: Path to store the analysis log (currently unused)
    :param excludeSignatures: List of signature types to exclude
    :param includeSignatures: List of signature types to include
    :param outputDirectory: Directory to extract files to
    :return: List of DetectedFile objects
    """
    if not checkFile(filePath):
        return []

    if outputDirectory != "" and not checkOutputDirectory(outputDirectory):
        return []
    
    try:
        # Call the Rust binwalk implementation (returns list of dicts)
        result_dicts = rust_run_binwalk(
            file_path=filePath,
            verbose=verbose,
            extract=extract,
            recursive=recursive,
            search_all=searchAll,
            exclude_signatures=excludeSignatures if excludeSignatures else None,
            include_signatures=includeSignatures if includeSignatures else None,
            output_directory=outputDirectory if outputDirectory else None,
        )
        
        # Convert dictionaries to DetectedFile objects
        detected_files = []
        for result_dict in result_dicts:
            # Extract extraction details if present
            extraction_details = None
            if result_dict.get("extraction_details"):
                ext_dict = result_dict["extraction_details"]
                extraction_details = ExtractedFile(
                    size=ext_dict.get("size", 0),
                    success=ext_dict.get("success", False),
                    extractor=ext_dict.get("extractor", ""),
                    outputDir=ext_dict.get("output_dir", "")
                )
            
            # Create DetectedFile object from dictionary
            df = DetectedFile(
                offset=result_dict["offset"],
                id=result_dict["id"],
                size=result_dict["size"],
                confidence=result_dict["confidence"],
                description=result_dict["description"],
                extractionDetails=extraction_details
            )
            detected_files.append(df)
        
        return detected_files
        
    except Exception as e:
        logger.error(f"Binwalk analysis failed: {e}")
        raise RuntimeError(f"Binwalk analysis failed: {e}") from e

