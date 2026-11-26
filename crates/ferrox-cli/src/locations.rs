//! The catalogue is public, so the listing is the binary's `edges` call. The
//! last answer is kept so the list still prints when the catalogue is down.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

use crate::args::{Options, Outbound, die};
use crate::config::{build_outbound, remembered_city, remembered_country};
use crate::lane::require_bin;
use crate::paths::{Paths, read_trim, secure_dir, write_private};

fn utf8(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned())
}

fn rows(bin: &Path, ping: bool) -> String {
    let mut command = Command::new(bin);
    command.arg("edges");
    if ping {
        command.arg("--ping");
    }
    command
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map_or_default(|output| utf8(output.stdout))
}

fn upper(text: &str) -> Cow<'_, str> {
    if text.chars().any(char::is_lowercase) {
        Cow::Owned(text.to_uppercase())
    } else {
        Cow::Borrowed(text)
    }
}

#[derive(Default)]
struct Place {
    edges: usize,
    best: Option<u64>,
}

impl Place {
    fn record(&mut self, reading: Option<u64>) {
        self.edges += 1;
        if let Some(ms) = reading {
            self.best = Some(self.best.map_or(ms, |current| current.min(ms)));
        }
    }
}

struct Catalogue {
    places: BTreeMap<String, BTreeMap<String, Place>>,
    total: usize,
    measured: bool,
    saved: String,
}

fn catalogue(text: &str, wanted: &str) -> Catalogue {
    let mut out = Catalogue {
        places: BTreeMap::new(),
        total: 0,
        measured: false,
        saved: String::with_capacity(text.len() + 1),
    };
    for line in text.lines() {
        let Ok(mut edge) = serde_json::from_str::<Value>(line) else {
            out.saved.push_str(line);
            out.saved.push('\n');
            continue;
        };
        let reading = ms_of(&edge);
        if let Some(object) = edge.as_object_mut() {
            object.remove("ms");
        }
        let _ = writeln!(out.saved, "{edge}");
        let country = upper(
            edge.get("country")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        );
        if country.is_empty() || (!wanted.is_empty() && country.as_ref() != wanted) {
            continue;
        }
        let city = upper(edge.get("city").and_then(Value::as_str).unwrap_or_default());
        out.total += 1;
        out.measured |= reading.is_some();
        if !out.places.contains_key(country.as_ref()) {
            let mut place = Place::default();
            place.record(reading.flatten());
            let mut cities = BTreeMap::new();
            cities.insert(city.into_owned(), place);
            out.places.insert(country.into_owned(), cities);
            continue;
        }
        let cities = out
            .places
            .get_mut(country.as_ref())
            .expect("the country was checked above");
        if let Some(place) = cities.get_mut(city.as_ref()) {
            place.record(reading.flatten());
        } else {
            let mut place = Place::default();
            place.record(reading.flatten());
            cities.insert(city.into_owned(), place);
        }
    }
    out
}

#[allow(clippy::option_option)]
fn ms_of(value: &Value) -> Option<Option<u64>> {
    let object = value.as_object()?;
    if !object.contains_key("ms") {
        return None;
    }
    Some(object.get("ms").and_then(Value::as_u64))
}

fn contains_ascii_ignore_case(haystack: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    !needle.is_empty()
        && haystack
            .as_bytes()
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

pub fn list(options: &Options, paths: &Paths, filter: &str, ping: bool) -> Result<(), String> {
    if options.outbound == Some(Outbound::Psiphon) {
        return psiphon_regions(options, paths, filter);
    }
    if options.outbound == Some(Outbound::Veepn) {
        return veepn_regions(paths, filter);
    }
    let bin = require_bin();
    secure_dir(&paths.conf_dir)
        .map_err(|error| format!("cannot create the config dir: {error}"))?;
    let wanted = filter.to_uppercase();
    let mut text = rows(&bin, ping);
    let fresh = !text.trim().is_empty();
    if !fresh {
        let Some(saved) = read_trim(&paths.locations_file) else {
            return Err(
                "the catalogue did not answer and no list is saved yet: check the network, then run 'ferrox-cli locations' again."
                    .to_owned(),
            );
        };
        println!(
            "the catalogue did not answer; showing the last list it gave ({}).",
            paths.locations_file.display()
        );
        text = saved;
    }
    let parsed = catalogue(&text, &wanted);
    if fresh {
        write_private(&paths.locations_file, &parsed.saved)
            .map_err(|error| format!("cannot save the catalogue: {error}"))?;
    }
    let Catalogue {
        places,
        total,
        measured,
        ..
    } = parsed;

    if places.is_empty() {
        if wanted.is_empty() {
            return Err(
                "the catalogue listed no dialable edge just now; the lane would refuse every country."
                    .to_owned(),
            );
        }
        return Err(format!(
            "{wanted} is not in the published catalogue; run 'ferrox-cli locations' for every country it lists."
        ));
    }

    let current_country = remembered_country(paths);
    let current_city = remembered_city(paths);
    println!(
        "exit locations from Mozilla's catalogue: {} countries, {total} edges",
        places.len()
    );
    println!(
        "country and city are the codes --country and --city take; * is what this machine remembers."
    );
    if ping {
        println!(
            "ms is one TCP handshake from this machine to the edge (1.5 s budget); 'no answer' is an edge that did not take it."
        );
        if !measured {
            println!(
                "latency not measured: this listing came from the offline copy; run 'locations --ping' again when the catalogue answers."
            );
        }
    }

    let print_country = |country: &str, cities: &BTreeMap<String, Place>| {
        let mark = if country == current_country.as_str() {
            "*"
        } else {
            " "
        };
        println!(
            " {mark} {country:<4} {:>3} edges{}",
            cities.values().map(|place| place.edges).sum::<usize>(),
            readable(country_reading(cities), ping, measured)
        );
        for (city, place) in cities {
            let star =
                if country == current_country.as_str() && city.as_str() == current_city.as_str() {
                    "*"
                } else {
                    " "
                };
            let label = if city.is_empty() {
                "any"
            } else {
                city.as_str()
            };
            println!(
                "   {star}   {label:<6} {:>3}{}",
                place.edges,
                readable(place.best, ping, measured)
            );
        }
    };
    if let Some(cities) = places.get("REC") {
        print_country("REC", cities);
    }
    for (country, cities) in &places {
        if country != "REC" {
            print_country(country, cities);
        }
    }
    println!();
    println!("remember one:  ferrox-cli location <CC> [CITY]");
    println!("the list is saved in {}", paths.locations_file.display());
    Ok(())
}

fn readable(reading: Option<u64>, ping: bool, measured: bool) -> String {
    if !ping || !measured {
        return String::new();
    }
    reading.map_or_else(
        || format!("{:>12}", "no answer"),
        |ms| format!("{ms:>9} ms"),
    )
}

fn country_reading(cities: &BTreeMap<String, Place>) -> Option<u64> {
    cities.values().filter_map(|place| place.best).min()
}

fn veepn_regions(paths: &Paths, filter: &str) -> Result<(), String> {
    secure_dir(&paths.conf_dir)
        .map_err(|error| format!("cannot create the config dir: {error}"))?;
    let wanted = filter.to_uppercase();
    let output = Command::new("curl")
        .args([
            "-q",
            "-sS",
            "--max-time",
            "20",
            "https://antpeak.com/v3/location/extension/",
        ])
        .output();
    let mut text = output
        .ok()
        .filter(|output| output.status.success())
        .map_or_default(|output| utf8(output.stdout));
    if text.trim().is_empty() {
        let Some(saved) = read_trim(&paths.veepn_locations) else {
            return Err(
                "the VeePN list did not answer and no list is saved yet: check the network, then run 'ferrox-cli locations --veepn' again."
                    .to_owned(),
            );
        };
        println!(
            "the VeePN list did not answer; showing the last list it gave ({}).",
            paths.veepn_locations.display()
        );
        text = saved;
    } else {
        write_private(&paths.veepn_locations, &format!("{}\n", text.trim_end()))
            .map_err(|error| format!("cannot save the VeePN list: {error}"))?;
    }
    let document = serde_json::from_str::<Value>(&text)
        .map_err(|_| "the VeePN list was not JSON".to_owned())?;
    let mut places: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for location in document
        .get("locations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let code = upper(
            location
                .get("countryCode")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        );
        let region = location
            .get("region")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if code.is_empty()
            || (!wanted.is_empty()
                && code.as_ref() != wanted.as_str()
                && upper(region).as_ref() != wanted.as_str())
        {
            continue;
        }
        let name = location
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if places.contains_key(code.as_ref()) {
            places
                .get_mut(code.as_ref())
                .expect("the country code was checked above")
                .push((region.to_owned(), name.to_owned()));
        } else {
            places.insert(
                code.into_owned(),
                vec![(region.to_owned(), name.to_owned())],
            );
        }
    }
    if places.is_empty() {
        if wanted.is_empty() {
            return Err("the VeePN list named no region just now.".to_owned());
        }
        return Err(format!(
            "{wanted} is not in the VeePN list; run 'ferrox-cli locations --veepn' for every code it lists."
        ));
    }
    let current = read_trim(&paths.veepn_location)
        .and_then(|line| line.split_whitespace().next().map(str::to_uppercase))
        .unwrap_or_default();
    println!(
        "exit locations from VeePN: {} countries, {} regions",
        places.len(),
        places.values().map(Vec::len).sum::<usize>()
    );
    println!(
        "the region id is what --region takes (lowercase); --country takes either it or the two-letter code."
    );
    for (code, regions) in &places {
        let mark = if *code == current { "*" } else { " " };
        println!(" {mark} {code}  {:>3} regions", regions.len());
        for (region, name) in regions {
            println!("      {region:<18} {name}");
        }
    }
    println!();
    println!("remember one:  ferrox-cli location --veepn <REGION>");
    println!("the list is saved in {}", paths.veepn_locations.display());
    Ok(())
}

fn psiphon_regions(options: &Options, paths: &Paths, filter: &str) -> Result<(), String> {
    let bin = require_bin();
    secure_dir(&paths.conf_dir)
        .map_err(|error| format!("cannot create the config dir: {error}"))?;
    let outbound = build_outbound(options, paths, None)?;
    let tmp = paths
        .state_dir
        .join(format!("psiphon-regions-{}.json", std::process::id()));
    secure_dir(&paths.state_dir)
        .map_err(|error| format!("cannot create the state dir: {error}"))?;
    let document = serde_json::json!({"inbounds": [], "outbounds": [outbound]});
    write_private(
        &tmp,
        &format!("{}\n", serde_json::to_string(&document).unwrap_or_default()),
    )
    .map_err(|error| format!("cannot write {}: {error}", tmp.display()))?;
    let output = Command::new(&bin)
        .arg("psiphon-regions")
        .arg("-c")
        .arg(&tmp)
        .output();
    let _ = std::fs::remove_file(&tmp);
    let wanted = filter.to_uppercase();
    let mut text = output
        .ok()
        .filter(|output| output.status.success())
        .map_or_default(|output| utf8(output.stdout));
    if text.trim().is_empty() {
        let Some(saved) = read_trim(&paths.psiphon_locations) else {
            return Err(
                "the Psiphon list did not answer and no list is saved yet: check the network, then run 'ferrox-cli locations --psiphon' again."
                    .to_owned(),
            );
        };
        println!(
            "the Psiphon list did not answer; showing the last list it gave ({}).",
            paths.psiphon_locations.display()
        );
        text = saved;
    } else {
        write_private(&paths.psiphon_locations, &format!("{}\n", text.trim_end()))
            .map_err(|error| format!("cannot save the Psiphon list: {error}"))?;
    }
    let mut rows = Vec::new();
    for line in text.lines() {
        let (code, count) = line.split_once('\t').unwrap_or((line, "0"));
        let code = upper(code.trim());
        if code.is_empty() || (!wanted.is_empty() && code.as_ref() != wanted.as_str()) {
            continue;
        }
        rows.push((code.into_owned(), count.trim().parse::<u64>().unwrap_or(0)));
    }
    if rows.is_empty() {
        if wanted.is_empty() {
            return Err("the Psiphon server list named no region just now.".to_owned());
        }
        return Err(format!(
            "{wanted} is not in the Psiphon server list; run 'ferrox-cli locations --psiphon' for every code it lists."
        ));
    }
    let current = read_trim(&paths.psiphon_location)
        .and_then(|line| line.split_whitespace().next().map(str::to_uppercase))
        .unwrap_or_default();
    println!(
        "exit regions from the signed Psiphon server list: {} codes",
        rows.len()
    );
    println!(
        "the code is what --psiphon-region takes; a code with no entry is not dialable from that list."
    );
    for (code, count) in &rows {
        let mark = if *code == current { "*" } else { " " };
        println!(" {mark} {code:<4} {count:>4} entries");
    }
    println!();
    println!("remember one:  ferrox-cli location --psiphon <CC>");
    println!("the list is saved in {}", paths.psiphon_locations.display());
    Ok(())
}

pub fn remember(options: &Options, paths: &Paths, country: &str, city: &str) -> Result<(), String> {
    let country = country.trim().to_uppercase();
    let city = city.trim().to_uppercase();
    if country.is_empty() {
        die(
            "usage: ferrox-cli location [--foxy|--veepn|--psiphon] <CC> [CITY]   (see 'ferrox-cli locations')",
        );
    }
    if options.outbound == Some(Outbound::Veepn) {
        if let Some(saved) = read_trim(&paths.veepn_locations) {
            let found = serde_json::from_str::<Value>(&saved).is_ok_and(|document| {
                document
                    .get("locations")
                    .and_then(Value::as_array)
                    .is_some_and(|locations| {
                        locations.iter().any(|location| {
                            let code = location
                                .get("countryCode")
                                .and_then(Value::as_str)
                                .unwrap_or_default();
                            let region = location
                                .get("region")
                                .and_then(Value::as_str)
                                .unwrap_or_default();
                            upper(code).as_ref() == country.as_str()
                                || upper(region).as_ref() == country.as_str()
                        })
                    })
            });
            if !found {
                die(&format!(
                    "'{country}' is not in the saved VeePN list; run 'ferrox-cli locations --veepn' to refresh it, or pick a region it prints."
                ));
            }
        }
        secure_dir(&paths.conf_dir)
            .map_err(|error| format!("cannot create the config dir: {error}"))?;
        write_private(
            &paths.veepn_location,
            &format!("{}\n", country.to_lowercase()),
        )
        .map_err(|error| format!("cannot remember the exit: {error}"))?;
        println!("exit remembered: {country}. The next 'up --veepn' moves there.");
        return Ok(());
    }
    if options.outbound == Some(Outbound::Psiphon) {
        if let Some(saved) = read_trim(&paths.psiphon_locations) {
            let found = saved.lines().any(|line| {
                line.split_once('\t')
                    .is_some_and(|(code, _)| code.eq_ignore_ascii_case(&country))
            });
            if !found {
                die(&format!(
                    "'{country}' is not in the saved Psiphon list; run 'ferrox-cli locations --psiphon' to refresh it, or pick a code it prints."
                ));
            }
        }
        secure_dir(&paths.conf_dir)
            .map_err(|error| format!("cannot create the config dir: {error}"))?;
        write_private(&paths.psiphon_location, &format!("{country}\n"))
            .map_err(|error| format!("cannot remember the exit: {error}"))?;
        println!("exit remembered: {country}. The next 'up --psiphon' moves there.");
        return Ok(());
    }
    if let Some(saved) = read_trim(&paths.locations_file) {
        let needle = format!("\"country\":\"{country}\"");
        if !contains_ascii_ignore_case(&saved, &needle) {
            die(&format!(
                "'{country}' is not in the saved catalogue list; run 'ferrox-cli locations' to refresh it, or pick a code it prints."
            ));
        }
    }
    secure_dir(&paths.conf_dir)
        .map_err(|error| format!("cannot create the config dir: {error}"))?;
    write_private(&paths.location_file, &format!("{country} {city}\n"))
        .map_err(|error| format!("cannot remember the exit: {error}"))?;
    if city.is_empty() {
        println!(
            "exit remembered: {country} (its catalogue order picks the city). The next 'up --foxy' moves there."
        );
    } else {
        println!("exit remembered: {country} / {city}. The next 'up --foxy' moves there.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{Place, catalogue, contains_ascii_ignore_case, country_reading, readable};

    #[test]
    fn a_silent_city_does_not_hide_a_measured_one() {
        let mut cities = BTreeMap::new();
        cities.insert(
            "SFO".to_owned(),
            Place {
                edges: 1,
                best: None,
            },
        );
        cities.insert(
            "IAD".to_owned(),
            Place {
                edges: 1,
                best: Some(21),
            },
        );
        assert_eq!(country_reading(&cities), Some(21));
    }

    #[test]
    fn a_catalogue_is_parsed_and_saved_once() {
        let text = concat!(
            "{\"country\":\"us\",\"city\":\"sfo\",\"ms\":21}\n",
            "{\"country\":\"US\",\"city\":\"IAD\",\"ms\":null}\n",
            "{\"country\":\"US\",\"city\":\"IAD\",\"ms\":9}\n",
            "not json\n",
        );
        let parsed = catalogue(text, "");
        assert_eq!(parsed.total, 3);
        assert!(parsed.measured);
        let us = &parsed.places["US"];
        assert_eq!(us["SFO"].edges, 1);
        assert_eq!(us["SFO"].best, Some(21));
        assert_eq!(us["IAD"].edges, 2);
        assert_eq!(us["IAD"].best, Some(9));
        assert_eq!(country_reading(us), Some(9));
        assert_eq!(parsed.saved.lines().count(), 4);
        assert!(!parsed.saved.contains("\"ms\""));
        assert!(parsed.saved.ends_with("not json\n"));
    }

    #[test]
    fn a_saved_catalogue_is_searched_without_lowercasing_it() {
        assert!(contains_ascii_ignore_case(
            "{\"country\":\"US\",\"city\":\"SFO\"}",
            "\"country\":\"us\""
        ));
        assert!(!contains_ascii_ignore_case(
            "{\"country\":\"GB\",\"city\":\"LHR\"}",
            "\"country\":\"US\""
        ));
    }

    #[test]
    fn an_offline_ping_renders_no_latency_column() {
        assert_eq!(readable(None, true, false), "");
        assert_eq!(readable(Some(21), true, false), "");
        assert!(readable(None, true, true).contains("no answer"));
        assert!(readable(Some(21), true, true).contains("21 ms"));
    }
}
