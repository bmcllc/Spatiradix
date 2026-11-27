//! W5: offline, read-only ISO 20022 inspection for synthetic lab documents.
//! No message generation, network, authentication, or financial state changes.
use crate::pix_json::{inspect_json, Context, PayloadKind};
use crate::pix_state::{rejection_impact, RejectionImpact};
use xml::reader::{EventReader, XmlEvent};

pub const MAX_XML_BYTES: usize = 131072;
type R<T> = Result<T, &'static str>;
const NS: &str = "urn:iso:std:iso:20022:tech:xsd:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Pacs008,
    Pain009,
    Pain012,
    Pain011,
    Pain013,
    Pain014,
    Camt055,
    Camt029,
}
impl Family {
    fn classify(s: &str) -> R<Self> {
        let p: Vec<_> = s
            .strip_prefix(NS)
            .ok_or("not ISO namespace")?
            .split('.')
            .collect();
        if p.len() != 4
            || p[2].len() != 3
            || p[3].len() != 2
            || !p[2..].iter().all(|s| s.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err("invalid namespace version format");
        }
        match (p[0], p[1]) {
            ("pacs", "008") => Ok(Self::Pacs008),
            ("pain", "009") => Ok(Self::Pain009),
            ("pain", "012") => Ok(Self::Pain012),
            ("pain", "011") => Ok(Self::Pain011),
            ("pain", "013") => Ok(Self::Pain013),
            ("pain", "014") => Ok(Self::Pain014),
            ("camt", "055") => Ok(Self::Camt055),
            ("camt", "029") => Ok(Self::Camt029),
            _ => Err("unsupported ISO family"),
        }
    }
    fn body(self) -> &'static str {
        match self {
            Self::Pacs008 => "FIToFICstmrCdtTrf",
            Self::Pain009 => "MndtInitnReq",
            Self::Pain012 => "MndtAccptncRpt",
            Self::Pain011 => "MndtCxlReq",
            Self::Pain013 => "CdtrPmtActvtnReq",
            Self::Pain014 => "CdtrPmtActvtnReqStsRpt",
            Self::Camt055 => "CstmrPmtCxlReq",
            Self::Camt029 => "RsltnOfInvstgtn",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    ChargeReference,
    MandateReference,
    RequestReference,
    EndToEndReference,
    Amount,
    Proxy,
    Status,
    Reason,
    CancellationStatus,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub family: Family,
    pub present: Vec<Field>,
    pub missing_selected: Vec<Field>,
    pub rejection_impact: Option<RejectionImpact>,
}
impl Observation {
    pub const fn is_verified(&self) -> bool {
        false
    }
}
#[derive(Default)]
struct Selected {
    values: Vec<(Field, String)>,
    transaction_groups: usize,
}
impl Selected {
    fn one(&self, f: Field) -> Option<&str> {
        let mut x = self.values.iter().filter(|(k, _)| *k == f);
        let a = x.next()?.1.as_str();
        if x.next().is_some() {
            None
        } else {
            Some(a)
        }
    }
    fn has(&self, f: Field) -> bool {
        self.values.iter().any(|(k, _)| *k == f)
    }
}
fn ends(path: &[String], suffix: &[&str]) -> bool {
    path.len() >= suffix.len()
        && path[path.len() - suffix.len()..]
            .iter()
            .map(String::as_str)
            .eq(suffix.iter().copied())
}
fn field(f: Family, p: &[String]) -> Option<Field> {
    use Family::*;
    use Field::*;
    let e = |s: &[&str]| ends(p, s);
    match f {
        Pacs008 => {
            if p.get(2).map(String::as_str) != Some("CdtTrfTxInf") {
                return None;
            }
            let e = |s: &[&str]| p.len() == 2 + s.len() && ends(p, s);
            if e(&["CdtTrfTxInf", "PmtId", "TxId"]) {
                Some(ChargeReference)
            } else if e(&["CdtTrfTxInf", "PmtId", "EndToEndId"]) {
                Some(EndToEndReference)
            } else if e(&["CdtTrfTxInf", "IntrBkSttlmAmt"]) {
                Some(Amount)
            } else if e(&["CdtTrfTxInf", "CdtrAcct", "Prxy", "Id"]) {
                Some(Proxy)
            } else {
                None
            }
        }
        Pain009 | Pain012 | Pain011 => {
            if e(&["Mndt", "MndtId"]) {
                Some(MandateReference)
            } else if e(&["Mndt", "MndtReqId"]) {
                Some(RequestReference)
            } else if e(&["Mndt", "ColltnAmt"]) {
                Some(Amount)
            } else if e(&["CxlRsn", "Rsn", "Prtry"]) {
                Some(Reason)
            } else if e(&["MndtSts"]) {
                Some(Status)
            } else {
                None
            }
        }
        Pain013 => {
            if e(&["PmtInf", "PmtInfId"]) {
                Some(ChargeReference)
            } else if e(&["CdtTrfTx", "PmtId", "EndToEndId"]) {
                Some(EndToEndReference)
            } else if e(&["MndtRltdInf", "MndtId"]) {
                Some(MandateReference)
            } else if e(&["CdtTrfTx", "Amt", "InstdAmt"]) {
                Some(Amount)
            } else {
                None
            }
        }
        Pain014 => {
            if e(&["OrgnlPmtInfId"]) {
                Some(ChargeReference)
            } else if e(&["TxInfAndSts", "OrgnlEndToEndId"]) {
                Some(EndToEndReference)
            } else if e(&["TxInfAndSts", "TxSts"]) {
                Some(Status)
            } else if e(&["TxInfAndSts", "StsRsnInf", "Rsn", "Prtry"]) {
                Some(Reason)
            } else {
                None
            }
        }
        Camt055 | Camt029 => {
            if e(&["OrgnlPmtInfId"]) {
                Some(ChargeReference)
            } else if e(&["OrgnlEndToEndId"]) {
                Some(EndToEndReference)
            } else if e(&["CxlRsnInf", "Rsn", "Prtry"]) {
                Some(Reason)
            } else if e(&["PmtInfCxlSts"]) {
                Some(CancellationStatus)
            } else {
                None
            }
        }
    }
}
fn expected(f: Family) -> &'static [Field] {
    use Family::*;
    use Field::*;
    match f {
        Pacs008 => &[ChargeReference, Amount, Proxy],
        Pain009 => &[MandateReference, RequestReference],
        Pain012 => &[MandateReference],
        Pain011 => &[MandateReference, Reason],
        Pain013 => &[ChargeReference, EndToEndReference, MandateReference, Amount],
        Pain014 => &[ChargeReference, EndToEndReference, Status],
        Camt055 => &[ChargeReference, EndToEndReference, Reason],
        Camt029 => &[ChargeReference, EndToEndReference, CancellationStatus],
    }
}
struct Frame {
    name: String,
    text: String,
    children: bool,
    brl: bool,
}
fn parse(input: &str) -> R<(Family, Selected)> {
    if input.len() > MAX_XML_BYTES || input.is_empty() {
        return Err("XML size outside limit");
    }
    // No DTD, CDATA or comments in this conservative subset; prevents entity declarations.
    if input.contains("<!") {
        return Err("XML declaration constructs not supported");
    }
    let mut stack: Vec<Frame> = Vec::new();
    let mut family = None;
    let mut namespace = String::new();
    let mut seen_body = false;
    let mut selected = Selected::default();
    let mut count = 0usize;
    for ev in EventReader::from_str(input) {
        match ev.map_err(|_| "malformed XML")? {
            XmlEvent::StartElement {
                name, attributes, ..
            } => {
                count += 1;
                if count > 4096 || stack.len() >= 32 {
                    return Err("XML complexity limit");
                }
                let ns = name.namespace.as_deref().ok_or("missing ISO namespace")?;
                if stack.is_empty() {
                    if family.is_some() || name.local_name != "Document" {
                        return Err("expected one Document root");
                    }
                    family = Some(Family::classify(ns)?);
                    namespace = ns.to_owned();
                } else {
                    if ns != namespace {
                        return Err("foreign namespace outside subset");
                    }
                    if stack.len() == 1 {
                        if seen_body || name.local_name != family.unwrap().body() {
                            return Err("message body/namespace mismatch");
                        }
                        seen_body = true;
                    }
                    stack.last_mut().unwrap().children = true;
                }
                if (family == Some(Family::Pacs008) && name.local_name == "CdtTrfTxInf")
                    || (family == Some(Family::Pain014) && name.local_name == "TxInfAndSts")
                {
                    selected.transaction_groups += 1;
                }
                let brl = attributes.iter().any(|a| {
                    a.name.local_name == "Ccy" && a.name.namespace.is_none() && a.value == "BRL"
                });
                stack.push(Frame {
                    name: name.local_name,
                    text: String::new(),
                    children: false,
                    brl,
                });
            }
            XmlEvent::Characters(s) | XmlEvent::Whitespace(s) => {
                if let Some(f) = stack.last_mut() {
                    if f.text.len() + s.len() > 8192 {
                        return Err("XML text limit");
                    }
                    f.text.push_str(&s);
                } else if !s.trim().is_empty() {
                    return Err("text outside root");
                }
            }
            XmlEvent::EndElement { .. } => {
                let f = stack.pop().ok_or("invalid XML stack")?;
                if !f.children {
                    let mut path: Vec<String> = stack.iter().map(|x| x.name.clone()).collect();
                    path.push(f.name);
                    if let Some(k) = field(family.ok_or("missing message family")?, &path) {
                        let v = f.text.trim();
                        if !v.is_empty() {
                            // For the comparison API only BRL settlement amounts are eligible.
                            if k == Field::Amount && family == Some(Family::Pacs008) && !f.brl {
                                return Err("expected BRL amount");
                            }
                            selected.values.push((k, v.to_owned()));
                        }
                    }
                } else if !f.text.trim().is_empty() {
                    return Err("mixed XML content not supported");
                }
            }
            XmlEvent::ProcessingInstruction { .. } | XmlEvent::CData(_) | XmlEvent::Comment(_) => {
                return Err("unsupported XML construct")
            }
            _ => {}
        }
    }
    if !seen_body || !stack.is_empty() {
        return Err("incomplete message");
    }
    Ok((family.ok_or("missing family")?, selected))
}
/// Recognize a family and inspect selected fields only. Not an XSD validator.
pub fn inspect_iso(input: &str) -> R<Observation> {
    let (family, fields) = parse(input)?;
    let mut present = Vec::new();
    for (f, _) in &fields.values {
        if !present.contains(f) {
            present.push(*f);
        }
    }
    let missing_selected = expected(family)
        .iter()
        .copied()
        .filter(|f| !fields.has(*f))
        .collect();
    let impact = if family == Family::Pain014
        && fields.transaction_groups == 1
        && fields.one(Field::Status) == Some("RJCT")
    {
        fields
            .one(Field::Reason)
            .and_then(|s| rejection_impact(s).ok())
    } else {
        None
    };
    Ok(Observation {
        family,
        present,
        missing_selected,
        rejection_impact: impact,
    })
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    Match,
    Mismatch,
    NotComparable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChargeComparison {
    pub reference: Comparison,
    pub amount: Comparison,
}
impl ChargeComparison {
    pub const fn is_verified(&self) -> bool {
        false
    }
}
fn cents(s: &str) -> Option<u64> {
    let (a, b) = s.split_once('.')?;
    if a.is_empty()
        || a.len() > 10
        || b.len() != 2
        || !a.bytes().chain(b.bytes()).all(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some(a.parse::<u64>().ok()? * 100 + b.parse::<u64>().ok()?)
}
/// Differential check against W2, for a single ordinary synthetic charge.
/// Does not compare creditor identity or authenticate either input.
pub fn compare_decoded_charge(xml: &str, json: &str, kind: PayloadKind) -> R<ChargeComparison> {
    if kind == PayloadKind::Rec {
        return Err("not an ordinary charge");
    }
    let (f, s) = parse(xml)?;
    if f != Family::Pacs008 {
        return Err("not a pacs.008 observation");
    }
    let p = inspect_json(json, kind, Context::Dynamic)?;
    if s.transaction_groups != 1 {
        return Ok(ChargeComparison {
            reference: Comparison::NotComparable,
            amount: Comparison::NotComparable,
        });
    }
    let reference = match s.one(Field::ChargeReference) {
        Some(v) if v == p.reference => Comparison::Match,
        Some(_) => Comparison::Mismatch,
        None => Comparison::NotComparable,
    };
    let amount = match (s.one(Field::Amount).and_then(cents), p.final_cents) {
        (Some(a), Some(b)) if a == b => Comparison::Match,
        (Some(_), Some(_)) => Comparison::Mismatch,
        _ => Comparison::NotComparable,
    };
    Ok(ChargeComparison { reference, amount })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn xml(f: &str, root: &str, inner: &str) -> String {
        format!(r#"<Document xmlns="{NS}{f}.001.01"><{root}>{inner}</{root}></Document>"#)
    }
    fn pacs(inner: &str) -> String {
        xml("pacs.008", "FIToFICstmrCdtTrf", inner)
    }
    fn cob() -> String {
        serde_json::json!({"revisao":0,"calendario":{"criacao":"2026-11-25T10:00:00Z","apresentacao":"2026-11-25T10:01:00Z"},"valor":{"original":"12.34"},"chave":"fixture@example.invalid","txid":"ABCDEFGHIJKLMNOPQRSTUVWXYZ","status":"ATIVA"}).to_string()
    }
    #[test]
    fn all_families() {
        for (f, r, k) in [
            ("pacs.008", "FIToFICstmrCdtTrf", Family::Pacs008),
            ("pain.009", "MndtInitnReq", Family::Pain009),
            ("pain.012", "MndtAccptncRpt", Family::Pain012),
            ("pain.011", "MndtCxlReq", Family::Pain011),
            ("pain.013", "CdtrPmtActvtnReq", Family::Pain013),
            ("pain.014", "CdtrPmtActvtnReqStsRpt", Family::Pain014),
            ("camt.055", "CstmrPmtCxlReq", Family::Camt055),
            ("camt.029", "RsltnOfInvstgtn", Family::Camt029),
        ] {
            let x = inspect_iso(&xml(f, r, "")).unwrap();
            assert_eq!(x.family, k);
            assert!(!x.missing_selected.is_empty());
            assert!(!x.is_verified());
        }
    }
    #[test]
    fn namespace_and_body() {
        assert!(inspect_iso(&xml("pain.009", "MndtCxlReq", "")).is_err());
        assert!(inspect_iso("<Document><x/></Document>").is_err());
        assert!(inspect_iso(&xml("pacs.999", "FIToFICstmrCdtTrf", "")).is_err());
    }
    #[test]
    fn prefixed_namespace() {
        let x=inspect_iso(r#"<i:Document xmlns:i="urn:iso:std:iso:20022:tech:xsd:pain.009.001.01"><i:MndtInitnReq/></i:Document>"#).unwrap();
        assert_eq!(x.family, Family::Pain009);
    }
    #[test]
    fn malformed() {
        for s in [
            "<x",
            "<x/> <x/>",
            "<!DOCTYPE x [<!ENTITY a 'x'>]><x/>",
            "<?probe x?><x/>",
        ] {
            assert!(inspect_iso(s).is_err());
        }
    }
    #[test]
    fn foreign_namespace() {
        assert!(inspect_iso(&pacs(r#"<X xmlns="urn:other"/>"#)).is_err());
    }
    #[test]
    fn depth_and_size() {
        assert!(inspect_iso(&"x".repeat(MAX_XML_BYTES + 1)).is_err());
        assert!(inspect_iso(&pacs(&format!("{}{}", "<X>".repeat(33), "</X>".repeat(33)))).is_err());
    }
    #[test]
    fn selected_paths() {
        let x=inspect_iso(&pacs(r#"<CdtTrfTxInf><PmtId><TxId>fixture</TxId></PmtId><IntrBkSttlmAmt Ccy="BRL">12.34</IntrBkSttlmAmt><CdtrAcct><Prxy><Id>fixture@example.invalid</Id></Prxy></CdtrAcct></CdtTrfTxInf>"#)).unwrap();
        assert!(x.missing_selected.is_empty());
        assert!(!format!("{x:?}").contains("fixture"));
    }
    #[test]
    fn wrong_path() {
        let x = inspect_iso(&pacs("<TxId>fixture</TxId>")).unwrap();
        assert!(!x.present.contains(&Field::ChargeReference));
    }
    #[test]
    fn rejection_w4() {
        let x=inspect_iso(&xml("pain.014","CdtrPmtActvtnReqStsRpt","<TxInfAndSts><TxSts>RJCT</TxSts><StsRsnInf><Rsn><Prtry>AC05</Prtry></Rsn></StsRsnInf></TxInfAndSts>")).unwrap();
        assert_eq!(x.rejection_impact, Some(RejectionImpact::ChargeAndAttempt));
    }
    #[test]
    fn unknown_rejection() {
        let x=inspect_iso(&xml("pain.014","CdtrPmtActvtnReqStsRpt","<TxInfAndSts><TxSts>RJCT</TxSts><StsRsnInf><Rsn><Prtry>OTHER</Prtry></Rsn></StsRsnInf></TxInfAndSts>")).unwrap();
        assert_eq!(x.rejection_impact, None);
    }
    #[test]
    fn comparison_w2() {
        let x=compare_decoded_charge(&pacs(r#"<CdtTrfTxInf><PmtId><TxId>ABCDEFGHIJKLMNOPQRSTUVWXYZ</TxId></PmtId><IntrBkSttlmAmt Ccy="BRL">12.34</IntrBkSttlmAmt></CdtTrfTxInf>"#),&cob(),PayloadKind::Cob).unwrap();
        assert_eq!(x.reference, Comparison::Match);
        assert_eq!(x.amount, Comparison::Match);
        assert!(!x.is_verified());
    }
    #[test]
    fn mismatch() {
        let x=compare_decoded_charge(&pacs(r#"<CdtTrfTxInf><PmtId><TxId>different</TxId></PmtId><IntrBkSttlmAmt Ccy="BRL">12.35</IntrBkSttlmAmt></CdtTrfTxInf>"#),&cob(),PayloadKind::Cob).unwrap();
        assert_eq!(x.reference, Comparison::Mismatch);
        assert_eq!(x.amount, Comparison::Mismatch);
    }
    #[test]
    fn duplicate_not_comparable() {
        let x = compare_decoded_charge(
            &pacs("<CdtTrfTxInf><PmtId><TxId>A</TxId><TxId>B</TxId></PmtId></CdtTrfTxInf>"),
            &cob(),
            PayloadKind::Cob,
        )
        .unwrap();
        assert_eq!(x.reference, Comparison::NotComparable);
    }
    #[test]
    fn currency_guard() {
        assert!(inspect_iso(&pacs(
            r#"<CdtTrfTxInf><IntrBkSttlmAmt Ccy="USD">12.34</IntrBkSttlmAmt></CdtTrfTxInf>"#
        ))
        .is_err());
    }

    #[test]
    fn separate_transactions_not_correlated() {
        let x=compare_decoded_charge(&pacs(r#"<CdtTrfTxInf><PmtId><TxId>ABCDEFGHIJKLMNOPQRSTUVWXYZ</TxId></PmtId></CdtTrfTxInf><CdtTrfTxInf><IntrBkSttlmAmt Ccy="BRL">12.34</IntrBkSttlmAmt></CdtTrfTxInf>"#),&cob(),PayloadKind::Cob).unwrap();
        assert_eq!(x.reference, Comparison::NotComparable);
        assert_eq!(x.amount, Comparison::NotComparable);
    }
    #[test]
    fn separate_rejection_groups_not_correlated() {
        let x=inspect_iso(&xml("pain.014","CdtrPmtActvtnReqStsRpt","<TxInfAndSts><TxSts>RJCT</TxSts></TxInfAndSts><TxInfAndSts><StsRsnInf><Rsn><Prtry>AC05</Prtry></Rsn></StsRsnInf></TxInfAndSts>")).unwrap();
        assert_eq!(x.rejection_impact, None);
    }
    #[test]
    fn nested_transaction_not_a_direct_mapping() {
        let x = inspect_iso(&pacs(
            "<Other><CdtTrfTxInf><PmtId><TxId>fixture</TxId></PmtId></CdtTrfTxInf></Other>",
        ))
        .unwrap();
        assert!(!x.present.contains(&Field::ChargeReference));
    }
}
