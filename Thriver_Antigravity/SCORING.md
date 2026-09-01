# 6-Factor Contextual Risk Scoring Model Specification

The core engine of **CIP-SOC** evaluates incident urgency using a 6-factor contextual risk formula.

---

## 1. Mathematical Scoring Formula

$$\text{Final Risk Score} = \min\left(100, \sum_{i=1}^{6} w_i \cdot N_i\right)$$

Where $w_i$ represents configurable weights that **MUST sum to 1.0**, and $N_i$ represents factor values normalized to the range $[0, 100]$.

---

## 2. Factor Definitions & Weights

| Factor Name | Variable | Default Weight | Range | Normalization Formula |
|---|---|---|---|---|
| **Severity** | $S$ | $0.25$ (25%) | 1 – 5 | $N_S = \frac{S - 1}{4} \times 100$ |
| **Asset Importance** | $A$ | $0.20$ (20%) | Tier 1–4 | Tier 1 = 100, Tier 2 = 75, Tier 3 = 50, Tier 4 = 25 |
| **Affected Users** | $U$ | $0.15$ (15%) | $u \ge 1$ | $N_U = 100 \times \frac{\log(1 + u)}{\log(1 + u_{\text{max}})}$ |
| **Data Sensitivity** | $D$ | $0.15$ (15%) | 1 – 5 | $N_D = \frac{D - 1}{4} \times 100$ |
| **Attack Confidence** | $C$ | $0.15$ (15%) | 0.0 – 1.0 | $N_C = C \times 100$ |
| **Business Impact** | $B$ | $0.10$ (10%) | 1 – 5 | $N_B = \frac{B - 1}{4} \times 100$ |

---

## 3. Priority Threshold Classification

- **CRITICAL**: $90.0 \le \text{Score} \le 100.0$ (SLA: 15 mins)
- **HIGH**: $75.0 \le \text{Score} < 90.0$ (SLA: 30 mins)
- **MEDIUM**: $50.0 \le \text{Score} < 75.0$ (SLA: 4 hours)
- **LOW**: $25.0 \le \text{Score} < 50.0$ (SLA: 24 hours)
- **INFORMATIONAL**: $0.0 \le \text{Score} < 25.0$

---

## 4. Pairwise Ranking Explanation Logic

When comparing Incident A (Score 82.34) against Incident B (Score 45.84):
1. Extract factor-by-factor contributions: $C_{i, A} = w_i \cdot N_{i, A}$ and $C_{i, B} = w_i \cdot N_{i, B}$.
2. Calculate contribution difference: $\Delta_i = C_{i, A} - C_{i, B}$.
3. Sort winning factors by largest positive $\Delta_i$.
4. Generate dynamic pairwise text narrative highlighting the major contextual drivers responsible for outranking.
