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
    
@dataclass
class ASoftware:
    name: str
    description: str = ""
    id: str = ""
    aliases: list = field(default_factory=list)
    platforms: list = field(default_factory=list)
    ref: str = ""
    
@dataclass
class ADatasource:
    name: str
    id: str = ""
    description: str = ""
    collection_layers: list = field(default_factory=list)
    platforms: list = field(default_factory=list)
    ref: str = ""
    
@dataclass
class ADatacomponent:
    name: str
    description: str = ""
    ref: str = ""
    
@dataclass
class AMitigation:
    name: str
    id: str = ""
    description: str = ""
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
        self.parse_software()
        self.parse_data_sources()
        self.parse_data_components()
        self.parse_mitigations()
        self.make_indices()

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

            data_sources = []
            if 'x_mitre_data_sources' in obj and obj['x_mitre_data_sources']:
                data_sources = obj['x_mitre_data_sources']
                
            tech = {
                'name': obj['name'],
                'platforms': obj['x_mitre_platforms'],
                'permissions_required': permissions,
                'defenses_bypassed': defense,
                'description': obj['description'],
                'detection': obj['x_mitre_detection'],
                'data_sources': data_sources,
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
            
    def parse_software(self):
        self.software = {}
        for obj in self.collections['malware']:

            if 'revoked' in obj and obj['revoked']: continue
            if 'x-mitre-deprecated' in obj and obj['x-mitre-deprecated']: continue
            
            id = Attack.get_id(obj['external_references'])
            
            soft = {
                    'name': obj['name'],
                    'id': id,
                    'ref': obj['id'],
                    'description': obj['description'],
                    'aliases': obj.get('x_mitre_aliases', []),
                    'platforms': obj.get('x_mitre_platforms', [])
                }

            asoft = ASoftware(**soft)

            self.software.update({
                id: asoft
            })
            
        for obj in self.collections['tool']:

            if 'revoked' in obj and obj['revoked']: continue
            if 'x-mitre-deprecated' in obj and obj['x-mitre-deprecated']: continue
            
            id = Attack.get_id(obj['external_references'])
            
            soft = {
                    'name': obj['name'],
                    'id': id,
                    'ref': obj['id'],
                    'description': obj['description'],
                    'aliases': obj.get('x_mitre_aliases', []),
                    'platforms': obj.get('x_mitre_platforms', [])
                }

            asoft = ASoftware(**soft)

            self.software.update({
                id: asoft
            })
            
    def parse_data_sources(self):
        self.data_sources = {}
        for obj in self.collections['x-mitre-data-source']:

            if 'revoked' in obj and obj['revoked']: continue
            if 'x-mitre-deprecated' in obj and obj['x-mitre-deprecated']: continue
            
            id = Attack.get_id(obj['external_references'])
                        
            ds = {
                    'name': obj['name'],
                    'id': id,
                    'ref': obj['id'],
                    'description': obj['description'],
                    'collection_layers': obj.get('x_mitre_collection_layers', []),
                    'platforms': obj.get('x_mitre_platforms', [])
                }

            ads = ADatasource(**ds)

            self.data_sources.update({
                id: ads
            })
            
    def parse_data_components(self):
        self.data_components = []
        for obj in self.collections['x-mitre-data-component']:

            parent_ref = obj['x_mitre_data_source_ref']
            parent_name = ""

            for ds in self.collections['x-mitre-data-source']:

                if ds['id'] == parent_ref:
                    parent_name = ds['name']
                    break    

            data = {
                'name': parent_name + ': ' + obj['name'],
                'description': obj['description'],
                'ref': obj['id']        
            }

            acomp = ADatacomponent(**data)
            self.data_components.append(acomp)
            
    def parse_mitigations(self):
        self.mitigations = {}
        for obj in self.collections['course-of-action']:

            if 'revoked' in obj and obj['revoked']: continue
            if 'x_mitre_deprecated' in obj and obj['x_mitre_deprecated']: continue
            
            id = Attack.get_id(obj['external_references'])
                        
            mit = {
                    'name': obj['name'],
                    'id': id,
                    'ref': obj['id'],
                    'description': obj['description'],
                }

            amit = AMitigation(**mit)

            self.mitigations.update({
                id: amit
            })
            
    def make_indices(self):
        self.techniques_by_group = {}
        self.groups_by_technique = {}
        self.soft_by_technique = {}
        self.mitigations_by_technique = {}
        self.techniques_by_soft = {}
        self.techniques_by_mitigation = {}
        self.techniques_by_data_component = {}
        self.data_components_by_technique = {}
        
        for grp in self.groups:
            self.techniques_by_group.update({
                grp: set()
            })

            for rel in self.relations:
                if (rel.src 
                    and rel.trg
                    and rel.src == grp 
                    and rel.type == 'uses' 
                    and rel.trg[:2] == 'T1'):
                    self.techniques_by_group[grp].add(rel.trg)


        for tech in self.techniques:
            self.groups_by_technique.update({
                tech: set()
            })
            self.soft_by_technique.update({
                tech: set()
            })
            self.mitigations_by_technique.update({
                tech: set()
            })
            for rel in self.relations:
                if (rel.src 
                    and rel.trg 
                    and rel.trg == tech
                    and rel.type == 'uses'
                    and rel.src[:2] == 'G0'):
                    self.groups_by_technique[tech].add(rel.src)
                if (rel.src 
                    and rel.trg 
                    and rel.trg == tech
                    and rel.type == 'uses'
                    and rel.src[:1] == 'S'):
                    self.soft_by_technique[tech].add(rel.src)
                if (rel.src 
                    and rel.trg 
                    and rel.trg == tech
                    and rel.type == 'mitigates'
                    and rel.src[:1] == 'M'):
                    self.mitigations_by_technique[tech].add(rel.src)

        
        for soft in self.software:
            self.techniques_by_soft.update({
                soft: set()
            })
            for rel in self.relations:
                if (rel.src 
                    and rel.trg
                    and rel.src == soft 
                    and rel.type == 'uses' 
                    and rel.trg[:2] == 'T1'):
                    self.techniques_by_soft[soft].add(rel.trg)

        
        for mit in self.mitigations:
            self.techniques_by_mitigation.update({
                mit: set()
            })
            for rel in self.relations:
                if (rel.src 
                    and rel.trg
                    and rel.src == mit 
                    and rel.type == 'mitigates' 
                    and rel.trg[:2] == 'T1'):
                    self.techniques_by_mitigation[mit].add(rel.trg)

        
        for dc in self.data_components:
            self.techniques_by_data_component.update({
                dc.name: set()
            })

        for rel in self.relations:
            if (rel.trg 
                and rel.trg[:2] == 'T1' 
                and rel.type == 'detects'):
                for d in self.data_components:
                    if d.ref == rel.source:
                        self.techniques_by_data_component[d.name].add(rel.trg)

        
        for tech in self.techniques:
            self.data_components_by_technique.update({
                tech: set()
            })
            for dc in self.techniques_by_data_component:
                if tech in self.techniques_by_data_component[dc]:
                    self.data_components_by_technique[tech].add(dc)