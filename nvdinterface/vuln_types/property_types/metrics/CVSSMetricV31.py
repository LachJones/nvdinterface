from typing import Optional

from .CVSSMetricV30 import CVSSMetricV30


class CVSSMetricV31(CVSSMetricV30):

    def __init__(
        self,
        attackVector: Optional[str] = None,
        attackComplexity: Optional[str] = None,
        privilegesRequired: Optional[str] = None,
        userInteraction: Optional[str] = None,
        scope: Optional[str] = None,
        confidentialityImpact: Optional[str] = None,
        integrityImpact: Optional[str] = None,
        availabilityImpact: Optional[str] = None,
        baseScore: Optional[float] = None,
        baseSeverity: Optional[str] = None,
        exploitCodeMaturity: Optional[str] = None,
        remediationLevel: Optional[str] = None,
        reportConfidence: Optional[str] = None,
        temporalScore: Optional[float] = None,
        temporalSeverity: Optional[str] = None,
        confidentialityRequirement: Optional[str] = None,
        integrityRequirement: Optional[str] = None,
        availabilityRequirement: Optional[str] = None,
        modifiedAttackVector: Optional[str] = None,
        modifiedAttackComplexity: Optional[str] = None,
        modifiedPrivilegesRequired: Optional[str] = None,
        modifiedUserInteraction: Optional[str] = None,
        modifiedScope: Optional[str] = None,
        modifiedConfidentialityImpact: Optional[str] = None,
        modifiedIntegrityImpact: Optional[str] = None,
        modifiedAvailabilityImpact: Optional[str] = None,
        environmentalScore: Optional[float] = None,
        environmentalSeverity: Optional[str] = None,
        vectorString: Optional[str] = None,
        **kwargs
    ):
        super().__init__(
            attackVector=attackVector,
            attackComplexity=attackComplexity,
            privilegesRequired=privilegesRequired,
            userInteraction=userInteraction,
            scope=scope,
            confidentialityImpact=confidentialityImpact,
            integrityImpact=integrityImpact,
            availabilityImpact=availabilityImpact,
            baseScore=baseScore,
            baseSeverity=baseSeverity,
            exploitCodeMaturity=exploitCodeMaturity,
            remediationLevel=remediationLevel,
            reportConfidence=reportConfidence,
            temporalScore=temporalScore,
            temporalSeverity=temporalSeverity,
            confidentialityRequirement=confidentialityRequirement,
            integrityRequirement=integrityRequirement,
            availabilityRequirement=availabilityRequirement,
            modifiedAttackVector=modifiedAttackVector,
            modifiedAttackComplexity=modifiedAttackComplexity,
            modifiedPrivilegesRequired=modifiedPrivilegesRequired,
            modifiedUserInteraction=modifiedUserInteraction,
            modifiedScope=modifiedScope,
            modifiedConfidentialityImpact=modifiedConfidentialityImpact,
            modifiedIntegrityImpact=modifiedIntegrityImpact,
            modifiedAvailabilityImpact=modifiedAvailabilityImpact,
            environmentalScore=environmentalScore,
            environmentalSeverity=environmentalSeverity,
            vectorString=vectorString,
            **kwargs
        )

        self._vector_pattern = "^CVSS:3[.]1/((AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])/)*(AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$"
        self._version = "3.1"
