# Verified primary readings

## What should ground adaptive authentication and resource authorization?

### Takeaway

Use resource-specific policy and historical login evidence. Public research data must be described according to its provenance, not treated as raw production telemetry. Readings were verified on 10 October 2026.

### Cited Findings

- Rose, Borchert, Mitchell and Connelly, *Zero Trust Architecture*, NIST SP 800-207 (2020), DOI `10.6028/NIST.SP.800-207`, treats authentication and authorization as distinct functions and rejects implicit network-location trust. — [NIST publication](https://csrc.nist.gov/pubs/sp/800/207/final)
- Wiefling, Jørgensen, Thunem and Lo Iacono, *Pump Up Password Security!*, DOI `10.1145/3546069`, studied 3.3 million users and 31.3 million attempts. Its journal reference is TOPS 26(1), Article 6 (2023); the authors' November 2022 version explains the earlier date used in their dataset citation. The paper shows that threshold configuration affects security and user friction. — [Author paper](https://arxiv.org/html/2206.15139v2), [Version metadata](https://arxiv.org/abs/2206.15139)
- The creator's public dataset contains more than 33 million **synthesized** attempts. Values are artificial; the creators discourage productive-system use. The dataset is CC BY 4.0 and publications using it should cite the associated paper. — [Creator repository and license](https://github.com/das-group/rba-dataset)

### Inferences

- Evaluate authentication challenge burden separately from binary attack classification. An approval vote is a business-policy decision, not independent proof that a login is legitimate.
- Use historical features computed before the current event. Retain the CSV digest, time ordering, cohort definition and missing-feature assumptions when comparing an external dataset.

### Gaps

- The project's seeded simulator is not independently validated login telemetry. The optional CSV adapter has not produced an external-data experiment in the available artifacts.
- No verified evidence currently supports real-world attack resistance, demographic fairness, user acceptance or organization-scale throughput for this implementation.

## What makes website sign-in interoperable and separate from permission?

### Takeaway

OAuth provides delegated access mechanisms; OIDC adds a standardized identity layer. Protect the code flow and verify identity before separately enforcing each requested resource permission.

### Cited Findings

- Sakimura, Bradley and Agarwal, RFC 7636 (2015), binds authorization-code redemption to a per-transaction verifier, mitigating intercepted-code redemption. — [RFC 7636](https://www.rfc-editor.org/info/rfc7636/)
- Lodderstedt, Bradley, Labunets and Fett, RFC 9700 (2025), requires PKCE for public clients, recommends it for confidential clients, and requires exact registered redirect matching. S256 avoids sending the verifier in the authorization request. — [OAuth security BCP](https://www.rfc-editor.org/info/rfc9700/)
- OIDC Core 1.0 incorporating errata set 2 defines ID-token issuer, audience, expiry and nonce checks, with issuer-provided verification keys. It supplies identity claims alongside OAuth's access flow. — [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html)
- OWASP explains practical code-flow, redirect, PKCE and token protection concerns. — [OAuth2 guidance](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)

### Inferences

- The relying party should store tokens and client secrets on its server, bind callback state to the browser's pending transaction, and call the permission API before protected content.
- Implementing a constrained code flow is a useful integration artifact but does not establish complete OIDC conformance or certification.

### Gaps

- No independent conformance suite or third-party provider interoperability result is available for this prototype.
- Public demo credentials, user-supplied context and displayed challenge codes still require replacement before a real identity deployment.

## What evidence supports the improved model and Web3 claims?

### Takeaway

Calibration, classification thresholds and authorization policy must be analyzed independently. An executable local contract proves EVM behavior under test, while single-host development infrastructure still retains administrator trust.

### Cited Findings

- Scikit-learn's calibration documentation explains reliability diagrams and notes that Brier loss combines reliability, discrimination and outcome uncertainty; lower Brier loss alone does not prove better calibration. Calibration data should be separate from model-fitting data. — [Probability calibration](https://scikit-learn.org/stable/modules/calibration.html)
- Zisad and Hasan, *LLMAC: A Global and Explainable Access Control Framework with Large Language Model* (2026), arXiv `2602.09392`, related CCNC DOI `10.1109/CCNC65079.2026.11366514`, reports 98.5% accuracy for its Mistral 7B system on synthetic policy scenarios. This is the authors' result, not a comparable measurement for Adaptive IAM. — [Primary paper and metadata](https://arxiv.org/abs/2602.09392)
- Ethereum documentation defines smart contracts as programs and state at on-chain addresses, invoked through transactions. This differs from a database hash chain. — [Smart-contract documentation](https://ethereum.org/developers/docs/smart-contracts/)
- Docker documents the container kernel/daemon trust boundary and the importance of restricted privileges. Containerization is not itself proof of complete isolation from the host administrator. — [Docker Engine security](https://docs.docker.com/engine/security/)
- The project's paired bootstrap reports Brier reduction and reduced legitimate friction, with lower suspicious challenge detection; F1's interval crosses zero. The independent candidate study retains the calibrated paper blend through validation and leaves the runtime model unchanged. — [Measured bootstrap](../../experiments/robustness.json), [Candidate study](../../experiments/candidate-study.json)

### Inferences

- A publishable contribution can center on reproducible policy/calibration tradeoffs, explicit authority boundaries and failure-state testing. Avoid claiming the first combination of ML, LLM, human approval and blockchain.
- Hashing identifiers reduces direct exposure but does not guarantee anonymity; low-entropy identities may still be guessed and hashes remain linkable.

### Gaps

- BERT and optional Ollama effectiveness are not measured. The held-out text classifier is weak and cannot justify automated authorization.
- Local chain tests cannot establish distributed Byzantine resilience, public-chain finality, privacy, production gas cost or availability.
- The project does not contain a systematic literature review proving absence of prior integrated systems. Other references from the supplied report remain unverified and should not enter the new bibliography as established facts.
