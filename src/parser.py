import os
import re
import xml.etree.ElementTree as ET
from typing import Dict, Generator, Any
from Evtx.Evtx import Evtx


def parse_event_xml(xml_str: str) -> Dict[str, Any]:
    """Converts a single Windows Event XML string into a flattened dictionary."""
    # Remove default XML namespace so ElementTree tag lookups stay clean
    xml_clean = re.sub(r'\sxmlns="[^"]+"', '', xml_str, count=1)
    root = ET.fromstring(xml_clean)

    event: Dict[str, Any] = {}

    # 1. Extract System metadata
    system = root.find("System")
    if system is not None:
        eid = system.find("EventID")
        tc = system.find("TimeCreated")
        comp = system.find("Computer")
        provider = system.find("Provider")

        event["EventID"] = int(eid.text) if (eid is not None and eid.text) else None
        event["TimeCreated"] = tc.attrib.get("SystemTime") if tc is not None else None
        event["Computer"] = comp.text if comp is not None else "Unknown"
        event["Provider"] = provider.attrib.get("Name") if provider is not None else "Unknown"

    # 2. Extract EventData key-value pairs
    event_data = root.find("EventData")
    if event_data is not None:
        for data in event_data.findall("Data"):
            name = data.attrib.get("Name")
            if name:
                event[name] = data.text if data.text is not None else ""

    return event


def stream_events(file_path: str) -> Generator[Dict[str, Any], None, None]:
    """
    Streams normalized event dictionaries from either:
      - Binary Windows Event Log (.evtx)
      - Exported Windows Event XML (.xml)
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")

    ext = os.path.splitext(file_path)[1].lower()

    if ext == ".evtx":
        with Evtx(file_path) as log:
            for record in log.records():
                try:
                    yield parse_event_xml(record.xml())
                except ET.ParseError:
                    continue

    elif ext == ".xml":
        with open(file_path, "r", encoding="utf-8") as f:
            raw_content = f.read()
        # Strip root <Events> wrapper if present and parse individual <Event> blocks
        raw_content = re.sub(r'\sxmlns="[^"]+"', '', raw_content)
        root = ET.fromstring(raw_content)
        events = root.findall(".//Event") if root.tag != "Event" else [root]
        for ev_elem in events:
            yield parse_event_xml(ET.tostring(ev_elem, encoding="unicode"))

    else:
        raise ValueError(f"Unsupported file extension '{ext}'. Use .evtx or .xml")