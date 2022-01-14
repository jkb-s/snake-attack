from json import loads, dumps
from requests import get
from types import SimpleNamespace
from dataclasses import dataclass, field

@dataclass
class ATechnique:
    name: str
    description: str = ""
    detection: str = ""
    data_sources: list = field(default_factory=list)
    platforms: list = field(default_factory=list)
    permissions_required: list = field(default_factory=list)
    defenses_bypassed: list = field(default_factory=list)
    id: str = ""
    tactics: list = field(default_factory=list)
    references: list = field(default_factory=list)
    ref: str = ""
    
@dataclass
class ARelation:
    source : str
    src: str
    target : str
    trg: str
    description: str
    type: str
    ref: str
    
@dataclass
class AGroup:
    name: str
    description: str = ""
    id: str = ""
    aliases: list = field(default_factory=list)
    ref: str = ""
    
    
class Attack:
    
    @staticmethod
    def get_id(references):
        for ref in references:
            if ref['source_name'] == 'mitre-attack':
                return ref['external_id']
        return None

    def __init__(self):
        self.load_config()                         # creates self.cfg
        self.download_attack(self.cfg.attack_data) # creates self.attack
        self.collect_objects()                     # creates self.collections
        self.parse_techniques()
        self.parse_groups()
        self.parse_relations()

    def load_config(self, filename='config.json'):
        with open(filename, 'r') as file:
            data = SimpleNamespace(**loads(file.read()))
            file.close()
        self.cfg = data

    def download_attack(self, url):
        response = get(url)
        if response.ok:
            self.attack = response.json()

    def collect_objects(self):
        self.collections = {}
        for obj in self.attack['objects']:
            tp = obj['type']
            if tp in self.collections:
                self.collections[tp].append(obj)
            else:
                self.collections.update({
                    tp: [obj]
                })

    def parse_techniques(self):
        self.techniques = {}
        self.techniques_list = []
        for obj in self.collections['attack-pattern']:

            if 'revoked' in obj and obj['revoked']: continue
            if 'x-mitre-deprecated' in obj and obj['x-mitre-deprecated']: continue

            id = Attack.get_id(obj['external_references'])

            tactics = []
            for tac in obj['kill_chain_phases']:
                if tac['kill_chain_name'] == 'mitre-attack':
                    tactics.append(
                        tac['phase_name']
                    )

            defense = []
            if 'x_mitre_defense_bypassed' in obj and obj['x_mitre_defense_bypassed']:
                defense = obj['x_mitre_defense_bypassed']

            permissions = []
            if 'x_mitre_permissions_required' in obj and obj['x_mitre_permissions_required']:
                permissions = obj['x_mitre_permissions_required']

            tech = {
                'name': obj['name'],
                'platforms': obj['x_mitre_platforms'],
                'permissions_required': permissions,
                'defenses_bypassed': defense,
                'description': obj['description'],
                'detection': obj['x_mitre_detection'],
                'tactics': tactics,
                'id': id,
                'ref': obj['id']
            }

            atech = ATechnique(**tech)
            self.techniques.update({
                id: atech
            })
            self.techniques_list.append(atech)
            
    def parse_groups(self):
        self.groups_list = []
        self.groups = {}
        for obj in self.collections['intrusion-set']:

            if 'revoked' in obj and obj['revoked']: continue
            if 'x-mitre-deprecated' in obj and obj['x-mitre-deprecated']: continue
            
            id = Attack.get_id(obj['external_references'])

            grp = {
                    'name': obj['name'],
                    'id': id,
                    'ref': obj['id'],
                    'description': obj['description'],
                    'aliases': obj['aliases']
                }

            agrp = AGroup(**grp)
            self.groups_list.append(agrp)
            self.groups.update({
                id: agrp
            })
    
    def parse_relations(self):
        self.relations = []
        for rel in self.collections['relationship']:
            data = {
                'source' : rel['source_ref'],
                'target' : rel['target_ref'],
                'description': rel.get('description', ''),
                'type': rel['relationship_type'],
                'ref': rel['id']
            }
            
            src_type = data['source'].split('--')[0]
            trg_type = data['target'].split('--')[0]
            
            src_id = None
            trg_id = None
            
            for obj in self.collections[src_type]:
                if obj['id'] == data['source']:
                    if 'external_references' in obj:
                        src_id = Attack.get_id(obj['external_references'])

            for obj in self.collections[trg_type]:
                if obj['id'] == data['target']:
                    if 'external_references' in obj:
                        trg_id = Attack.get_id(obj['external_references'])
            
            data.update({
                'src': src_id, 'trg': trg_id
            })
            
            self.relations.append(
                ARelation(**data)
            )