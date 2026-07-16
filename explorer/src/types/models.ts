export type Severity = 'low' | 'medium' | 'high' | 'critical'

export type AlertType = 'ttp_alert' | 'campaign_alert' | 'summary_digest'

export type IntelligenceTier = 'observable' | 'indicator' | 'ttp'

export type FraudCategory =
  | 'mfa_bypass'
  | 'synthetic_identity'
  | 'phishing_kit'
  | 'cnp_fraud'
  | 'account_takeover'
  | 'new_account_fraud'
  | 'recurring_billing_fraud'
  | 'money_mule'
  | 'investment_fraud'
  | 'social_engineering'

export type SourceType =
  | 'tor_hidden_service'
  | 'i2p_site'
  | 'telegram_channel'
  | 'forum_post'
  | 'marketplace'
