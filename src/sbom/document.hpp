#pragma once
#include <string>
#include <vector>

#include "core/model.hpp"

namespace bomwerk::sbom
{

/// One SBOM document as read back off disk: the component list plus the
/// document-level identity fields a consumer (a product
/// selection today, the `bomwerk report` later) may want without
/// re-deriving them from `components` itself.
///
/// This is a READER-side type only: the inverse of `output::write_cyclonedx`,
/// not a replacement for it. It deliberately carries far less than
/// `core::Component` does at scan time: a finished SBOM never recorded most of
/// it, so there is nothing here to read back. The one exception is
/// `Component::root`, which the writer emits as CycloneDX
/// `evidence.occurrences[].location` and this reader to restore: a build
/// trace has to have somewhere to attribute its compiles, and re-scanning the
/// repository to rediscover roots would make `bomwerk trim` a second copy of
/// `bomwerk scan`. Scan-time `evidence` is still not carried: each component
/// gets one "SBOM input" entry instead (see `read.cpp`).
struct SbomDocument
{
  std::vector<core::Component> components;
  std::string product_id;           ///< metadata.component.name; empty if absent
  std::string product_version;      ///< metadata.component.version; empty if absent
  std::string manufacturer_name;    ///< metadata.manufacturer.name; empty if absent
  std::string manufacturer_email;   ///< first metadata.manufacturer.contact[].email
  std::string generated_timestamp;  ///< metadata.timestamp (ISO-8601); empty if absent
  std::string serial_number;        ///< document serialNumber; empty if absent
};

}  // namespace bomwerk::sbom
