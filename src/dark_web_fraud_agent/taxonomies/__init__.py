"""Custom taxonomy definitions for the Dark Web Fraud Agent.

Taxonomy JSON files in this package follow the MISP taxonomy format with
namespace, predicates, and values arrays. They can be loaded directly from
the filesystem or uploaded to S3 for runtime loading by the TaggingEngine.
"""

import importlib.resources as _resources


def get_banking_fraud_taxonomy_path() -> str:
    """Return the filesystem path to the banking fraud taxonomy JSON.

    Useful for testing and for uploading to S3 during deployment.
    """
    ref = _resources.files(__package__).joinpath("banking_fraud.json")
    return str(ref)
