{******************************************************************************}
{  Argon2StressGolden.inc - valores-ouro gerados pela referencia C oficial        }
{  (oracle_grid.c, phc-winner-argon2-20190702). NAO EDITAR A MAO.                 }
{  Entrada: pwd = 16 x 0x01, salt = 16 x 0x02, tag = 32 bytes.                    }
{******************************************************************************}
const
  GOLDEN_COUNT = 120;
  GOLDEN: array [0 .. GOLDEN_COUNT - 1] of TGolden = (
    (AType: Argon2_i; Version: 16; MCost: 8; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: '445c7fdbed3513f49f28adcf0909203de5958af35068716e316dd57de223c567'),
    (AType: Argon2_i; Version: 16; MCost: 8; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: '100baf1af7008683c0810a07a0dd86c303aba5a23a344a32ae911b6a9eb4c166'),
    (AType: Argon2_i; Version: 16; MCost: 256; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: 'e4d65cb2f45af97169884e6728427ff20e6022d4fe83d891b1edb6b25097ef76'),
    (AType: Argon2_i; Version: 16; MCost: 256; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: '8734af563f639b3704e424802fd4fafface29efd422bae2ebc229c4884919cfc'),
    (AType: Argon2_i; Version: 16; MCost: 256; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: 'fea58413372531c2ecfbf668c5493b39d88b1473d847f322efa101c1ca9aaa5d'),
    (AType: Argon2_i; Version: 16; MCost: 256; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: 'b0cb7a632899f6109eb57258b2f553383dd88bf966c7bf9963dbec205daa1328'),
    (AType: Argon2_i; Version: 16; MCost: 256; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: '8cc3ed7d0951bd6ebe680751c8a7f8656b88f3c99737f22ae3f8ff0c31af43d9'),
    (AType: Argon2_i; Version: 16; MCost: 256; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: 'eb62306e260eed0797ed435355146f5fa52579b9a8bfb3368f255441701101ce'),
    (AType: Argon2_i; Version: 16; MCost: 16384; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: '9972fd3496c1915dac9e380f77cd1e7611fdc6788a7480cbdbb96075e83e4a31'),
    (AType: Argon2_i; Version: 16; MCost: 16384; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: '0cde59f4b2eaefae30ef2a37873b376688f53004728f1682368a7b82674065ff'),
    (AType: Argon2_i; Version: 16; MCost: 16384; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: '6e2e1b7591484d1213f277ba5cc81b86688c2c0ec4ec69c1d4548fb6e09e7a4b'),
    (AType: Argon2_i; Version: 16; MCost: 16384; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: '4ce1ebe5fa325e387580e6d79c0d08ef3d940ff0a4993ea632639efc3acb6759'),
    (AType: Argon2_i; Version: 16; MCost: 16384; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: 'eca39aaf20c7a0fa2fd42850e846b8fa7a8009af901c0f55f67a462d73598fe5'),
    (AType: Argon2_i; Version: 16; MCost: 16384; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: 'edfecbf44dafbcfc9ef9e6584519dfbf751c30b43f3bba105a93b7e21608a7eb'),
    (AType: Argon2_i; Version: 16; MCost: 65536; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: '75a5199bc0a7ab9779380d09395cfb36b5a01341acb67a3c7afdcd121057ebb3'),
    (AType: Argon2_i; Version: 16; MCost: 65536; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: 'c334c2a55970415ff84709c2b716422f9846e45178588a2fff891fbd7715078c'),
    (AType: Argon2_i; Version: 16; MCost: 65536; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: 'b18f6e94141ea5021e446f9c18cc0a0620f5b30fb9451809057a1ff5ed860af2'),
    (AType: Argon2_i; Version: 16; MCost: 65536; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: '6e0e860afdbe9ca3244b925abd452ad0599cb88f1d781927d135897c9084dce1'),
    (AType: Argon2_i; Version: 16; MCost: 65536; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: 'd923c12de35982d0a084cc6eda542a9d3e8e0a5c5838480de0cbdbca38497d40'),
    (AType: Argon2_i; Version: 16; MCost: 65536; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: '0915a7bbf6196e25dffd79135f8ab6cafef2b07c9be57528ee185f8046986e21'),
    (AType: Argon2_i; Version: 19; MCost: 8; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: '1a7e672055b74a9884744ccaa90c2a43c0517e75e8a961bc2a9bd2a3c70b246a'),
    (AType: Argon2_i; Version: 19; MCost: 8; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: 'fdff44a5b542fec87d4133473dbcbd041326d0452363d50e152042666828537e'),
    (AType: Argon2_i; Version: 19; MCost: 256; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: '6b35300879441709a61a511aefb6c45779ffc5da61c53aaedee2d80615e2523c'),
    (AType: Argon2_i; Version: 19; MCost: 256; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: '5127c8d337f1535d09fec501b10abdc63abab4bd820519115a649fd3bf2a6f2c'),
    (AType: Argon2_i; Version: 19; MCost: 256; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: 'de32e423ac237c4860dd4b20d5ae921a4fbb28a21c24690f9c1d54e9edd24c6a'),
    (AType: Argon2_i; Version: 19; MCost: 256; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: 'be64b6fb11984969d705ced2f608723b8939089d40175f8a243796a8a6b5acaa'),
    (AType: Argon2_i; Version: 19; MCost: 256; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: 'e1da87fe6ba3e190731092d4ecb85b26a5abb7913e081bae42d59ee8dd98e621'),
    (AType: Argon2_i; Version: 19; MCost: 256; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: 'ec1cb9c67e022a32118faf7653d4cf308e5c6d5be08fb5dbd69763386b7b98dd'),
    (AType: Argon2_i; Version: 19; MCost: 16384; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: '4f5380f121974edd7b91708f0cf344c868e8f1c1ec74e5dda7ca7d449d344433'),
    (AType: Argon2_i; Version: 19; MCost: 16384; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: 'd47bbfc9d239980d112a573490b76f4758181d314978ab75bc6dd5f72964e219'),
    (AType: Argon2_i; Version: 19; MCost: 16384; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: '49a6c2d140d5efbc8516be0ccb384b4c970a3e54b3d27b1989cdedd98c9a07fb'),
    (AType: Argon2_i; Version: 19; MCost: 16384; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: '1fcecea4529e7954b8e2e5b40e881db7967b9a1e753ac150aa774de9b9922fd9'),
    (AType: Argon2_i; Version: 19; MCost: 16384; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: '97316dcedbe5cc1063d9f2d6f9d823582be88df930f12eb71c12c36c451ca888'),
    (AType: Argon2_i; Version: 19; MCost: 16384; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: 'fcfb6d86477e16e17f99f70a596286f3041b8e6263b6a5d7cd15068b48c36f60'),
    (AType: Argon2_i; Version: 19; MCost: 65536; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: 'd10ebd38b808b6608d8b3fa688723c40be857b9dafb333e61c720eaa4c4d3314'),
    (AType: Argon2_i; Version: 19; MCost: 65536; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: '93aeae3f685daf7a80a63001f4eb1b7a738cd5231ac08721411df92112b28c33'),
    (AType: Argon2_i; Version: 19; MCost: 65536; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: '6cd7e3e59abd337cd928e30ab8620bdf2af1977a2474ed233a52b3c5f00aa497'),
    (AType: Argon2_i; Version: 19; MCost: 65536; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: 'b533d1e1b16d24762a7e305bf6be20a6b3442decf4b06710442c2ffc124819d6'),
    (AType: Argon2_i; Version: 19; MCost: 65536; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: 'f44b81378e086da6c4380e810eed006453a280356d721b0622526aac7d74ee48'),
    (AType: Argon2_i; Version: 19; MCost: 65536; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: '538e74036192d88312db9592b8fba2fc14e22b0c7b2bca80acfff0f1cbd271c9'),
    (AType: Argon2_d; Version: 16; MCost: 8; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: '1b6f499db32578f1d661c1d4bf43184116d5356ec79e41d4d3627eecd485d7b1'),
    (AType: Argon2_d; Version: 16; MCost: 8; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: 'fca1141da2f7046d9712f23d2dd215a5fe3b61f2889180040b6ee7e4aa25bf46'),
    (AType: Argon2_d; Version: 16; MCost: 256; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: '08c1c6f2e313362a475c9c5f75228e9d7b2520b741e0d05e21bc7086436613ba'),
    (AType: Argon2_d; Version: 16; MCost: 256; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: '179f853f81c60f37afe33c1ebffab96b540b0f6225507d08c05d74609dcac93d'),
    (AType: Argon2_d; Version: 16; MCost: 256; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: '370f8e5fa4e50bca35d13a55893114a798daca7632f4a7df8bc3c493f2826921'),
    (AType: Argon2_d; Version: 16; MCost: 256; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: '36bc6f65faba2a66a5d98dff8e250c60fcf2deadba573391fd032b6d5c57e9f3'),
    (AType: Argon2_d; Version: 16; MCost: 256; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: '75b8222b4f4ec99249f4be24091f38e318de0449878c5c7c59414f1b1ed17319'),
    (AType: Argon2_d; Version: 16; MCost: 256; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: 'e27dc737ea8daa2454fadddfcaeb24da53af7d4a28613caf0f44083203314440'),
    (AType: Argon2_d; Version: 16; MCost: 16384; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: 'e8260c0eb2cf727d0abf9f50503fac6f8cfa59269fb53bb838dcfc93d62c2c38'),
    (AType: Argon2_d; Version: 16; MCost: 16384; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: '586bc8d9adbcb70d5a5260bb91f69acbba251a2402767597d7fe32bebad64cea'),
    (AType: Argon2_d; Version: 16; MCost: 16384; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: 'cacb1827b5e70a5bf7138f6a2538089ab0ee63d58ec07b1484e11b266d73f96f'),
    (AType: Argon2_d; Version: 16; MCost: 16384; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: '7560d4b525d7f42e8e5681d3bcc7f2bf37db7903eafd2df043f002a62bd2d310'),
    (AType: Argon2_d; Version: 16; MCost: 16384; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: 'a86ae1505adc4ff95703f0194a92cf5e1ff171edd644716f2c49922afcb0f6f2'),
    (AType: Argon2_d; Version: 16; MCost: 16384; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: '54c0137eaceb46476bed05283c055c47ce783df9e71233a22e81e34d8e9d2658'),
    (AType: Argon2_d; Version: 16; MCost: 65536; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: '21b7827a1464c2ee31bbb8599f02d344a9681fc6c51f1fbccd9c0902344767de'),
    (AType: Argon2_d; Version: 16; MCost: 65536; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: 'f6e7f34af409cb4d0557d2ecc67e1662e272489ee8d70377acb90d5b4e69bd6f'),
    (AType: Argon2_d; Version: 16; MCost: 65536; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: '4318119b251531dca3d84fd822fd3c00ca2bcbcf4a0ddd64eb03750a2b30034e'),
    (AType: Argon2_d; Version: 16; MCost: 65536; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: 'f84c5e4a82cb3cca3c791fa948e0313780d85d5ceaf6882edfffa4104a24551f'),
    (AType: Argon2_d; Version: 16; MCost: 65536; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: '69648dc585f925058968ceefade44de436892ba9b4dabe6d376e1997d930144f'),
    (AType: Argon2_d; Version: 16; MCost: 65536; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: '62d896229b7f1c6a4ea3426d5591da2f8fa9fdd5f1d5747bfa157fa3eda13255'),
    (AType: Argon2_d; Version: 19; MCost: 8; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: 'a63e8f6844f6833e7d77e73c23cf5f22c8dc81cfd6f716bd99e7f24bd7b4586d'),
    (AType: Argon2_d; Version: 19; MCost: 8; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: '83496391bbfd7cdc148b1a16898040dd0f52fb0b39d7607df3a736e96242be7d'),
    (AType: Argon2_d; Version: 19; MCost: 256; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: '482067badabf248e0e2c2eef69500cb6514403b4b17f6fb98fa6dff4850924d3'),
    (AType: Argon2_d; Version: 19; MCost: 256; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: 'e2f6be46005876c2d10ed28175719aa2ef8a7daf8f512ee1f6062963384175ca'),
    (AType: Argon2_d; Version: 19; MCost: 256; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: '20a5fd8910f6a7edf771591fbea866c028b7d1c1e0e402ad997a18e90ecdb881'),
    (AType: Argon2_d; Version: 19; MCost: 256; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: '1f521674507cce1dd63fc88bacce329151631a732cfa8404e2bcf427d7e45b4c'),
    (AType: Argon2_d; Version: 19; MCost: 256; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: '7c621814eb4728eba394fae585ba53db55589f44b8d3787968aa95c04072d259'),
    (AType: Argon2_d; Version: 19; MCost: 256; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: 'c5c2fce88bca70e28840ceefccc3a652dfdcf9497fdf37f71e88899377dbe73d'),
    (AType: Argon2_d; Version: 19; MCost: 16384; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: 'e9500d71086a87cf8f3749936a20a44ff35ee829c7c05568d4253d49d1fd55d3'),
    (AType: Argon2_d; Version: 19; MCost: 16384; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: 'dafba5673c5e815ba9401d282b3194d8adf35de2843bb7205a9e35f0f0d4b87c'),
    (AType: Argon2_d; Version: 19; MCost: 16384; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: '7868e06c616d7ace3ba75670660cc29691a5a8165ca309f8afc7d18497a8e519'),
    (AType: Argon2_d; Version: 19; MCost: 16384; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: 'b748ee2c6edecc0850962cd9b532ca5894fb52e00773b05f0291cc63741e168d'),
    (AType: Argon2_d; Version: 19; MCost: 16384; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: 'b6424bd109cfffc0ea11ec5a0ab730b01a2f3fcc057b2dab83556309c7a2402a'),
    (AType: Argon2_d; Version: 19; MCost: 16384; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: 'f0b0bf27f0f8b6057d5fe0aaf5209c1feab9207f6412cd54c03a3c6c3aa65b36'),
    (AType: Argon2_d; Version: 19; MCost: 65536; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: '11fcddd5e8696497396d456c7701ea205d17f7f9702c4906d0e24df0d2220fc5'),
    (AType: Argon2_d; Version: 19; MCost: 65536; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: '5470b003fd382b161266d3187158d7defec7b892225e1b7165fba7c92de5aada'),
    (AType: Argon2_d; Version: 19; MCost: 65536; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: '4dc0784a49fcd7947e3cb1890e51198dd6a7a02ac51ef40433eeda4c893ac6c6'),
    (AType: Argon2_d; Version: 19; MCost: 65536; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: '953b980c9ae5f45517a33dcb62031900abe0136cd46f499b24b06a6886e590bd'),
    (AType: Argon2_d; Version: 19; MCost: 65536; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: '8c4b35e894c46c3ef318f2675c982ab86410f9dd446bd94b70bd6379b6c4cd47'),
    (AType: Argon2_d; Version: 19; MCost: 65536; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: 'd10c291d240173511d46e479ad93470ec773c710de94741ece4205ddb32552ab'),
    (AType: Argon2_id; Version: 16; MCost: 8; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: '244154a96254c6575c0761308db178c0881691da81a04dd0ba6509930d1d1862'),
    (AType: Argon2_id; Version: 16; MCost: 8; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: '0f72edb3e7b80d64343daf0f7627db3c5ea10b5f47d6702310c6a1baa349104a'),
    (AType: Argon2_id; Version: 16; MCost: 256; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: '3b90e97fb49868a169e0f2dd1a7fe0a593ab0a4510e220232ba2d09220dd73a4'),
    (AType: Argon2_id; Version: 16; MCost: 256; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: '6530a19ddd45bb6851d394c7f77cf302fed1355f88240c784e0ca0a825d02446'),
    (AType: Argon2_id; Version: 16; MCost: 256; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: 'ccbbecaf40298b5080de079a09fb1cd55f8e1e4013ee8347014cbc2880f5456a'),
    (AType: Argon2_id; Version: 16; MCost: 256; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: 'b53f22ff200b3719c8f1900af0dec2b571d80b8effa9a9908e0e51e725231ae2'),
    (AType: Argon2_id; Version: 16; MCost: 256; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: '59615d56d466e616419999a5e248e8c9440de85458ab938ed2a41517d8642032'),
    (AType: Argon2_id; Version: 16; MCost: 256; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: '7a1122c348be28b6c6b041e2009dbdfb4a0e196a20f96c526fce4fa9c23df71d'),
    (AType: Argon2_id; Version: 16; MCost: 16384; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: '216670dd866419d333190f9bfde0f1184bfca1914352446ff89974d90f04e7e1'),
    (AType: Argon2_id; Version: 16; MCost: 16384; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: '62b45e2b47b6eebaf70a32ee98b5f941e622c6d6e9d46f1999f9d50dccdc5873'),
    (AType: Argon2_id; Version: 16; MCost: 16384; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: '663fb6a96367a4164fcca1ad6c485121252b3e693a9aef1eecd05f43982e00a3'),
    (AType: Argon2_id; Version: 16; MCost: 16384; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: 'd74df2c16273c97e179162db467c92f13b7d9ada1376f3aef88fa2db0eaef350'),
    (AType: Argon2_id; Version: 16; MCost: 16384; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: '76525adc031d900f44fcd00cebe3e319cfd1441ea53654eb11bfadf374c3fc0c'),
    (AType: Argon2_id; Version: 16; MCost: 16384; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: '6666719d4f3cde517a4122a8600e488095f1af9fb017ef74fe4dbf65ef0114c9'),
    (AType: Argon2_id; Version: 16; MCost: 65536; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: '396d5a072fcff17d0d5c18aebbebe6dcf62705da7cd933ed2118ea18cca7e4e5'),
    (AType: Argon2_id; Version: 16; MCost: 65536; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: 'dcf552a63f8f3f238abb5ab90ffcf513716a60c1699a9c039753a35d9b75ce6a'),
    (AType: Argon2_id; Version: 16; MCost: 65536; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: 'a49ec4e22635a6a21cc57cf28120750352b2265294064264d526eb4df7bfc2d5'),
    (AType: Argon2_id; Version: 16; MCost: 65536; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: '5b4e5d928a401b3750ec3853311ef8a433a37045143f6a31f01989ef9e0e6c1c'),
    (AType: Argon2_id; Version: 16; MCost: 65536; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: '1d2d14b143c9a7f3482189cc7ee4a097a8985bec1ea279064e03ce627703a29a'),
    (AType: Argon2_id; Version: 16; MCost: 65536; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: 'cdc3f4857620e1a200323f889651e2eee4af1d3bcc140212e7f822ae83a78e20'),
    (AType: Argon2_id; Version: 19; MCost: 8; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: '59e83063be6cfcae60054d6acdf55b67aec8707a87958a8e4ef5e0a899f8d8fb'),
    (AType: Argon2_id; Version: 19; MCost: 8; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: '2d0f0f42c20fc836e992884418c5a5c84172fbab4ac15c98ab7c6f87a876d6df'),
    (AType: Argon2_id; Version: 19; MCost: 256; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: 'c3c9379bea0a4f0c0c305c9a5c86e71650500151df987d9e0b5f7225e3c9e727'),
    (AType: Argon2_id; Version: 19; MCost: 256; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: '00294315a2a34d4e9f5291f974949ef66b65a9ba1279fee89d5be6b177daf2fc'),
    (AType: Argon2_id; Version: 19; MCost: 256; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: '34688a0bff63136d6833fd27e7bddab49a4f605904155d66b1fd4243f7a91f8a'),
    (AType: Argon2_id; Version: 19; MCost: 256; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: 'bff2f310b0dc4791b95b6285248fb844b25d82e2d27f30a41786000f03eaedee'),
    (AType: Argon2_id; Version: 19; MCost: 256; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: '34f5549c7a3bf7414f39b7a1513c8c0eac06ca0a755c1948679010dd5243ffc1'),
    (AType: Argon2_id; Version: 19; MCost: 256; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: '3445fdc0511323fda9bffaceff6dd395251cddf0a8026717ff56c9fe3f1dc593'),
    (AType: Argon2_id; Version: 19; MCost: 16384; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: 'e20bc8ec371918595c8ac10d771b9ced70f1eb6fd8389a09f6fb8fb828b07eac'),
    (AType: Argon2_id; Version: 19; MCost: 16384; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: '6099fb3d774fcb20be45f178a65cf3d15718fd86463803d3704d04e59dbf91c3'),
    (AType: Argon2_id; Version: 19; MCost: 16384; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: '99d0253fcf0823805ff4ee2d024786ef707bfe76083d26ef55df74efd42fb88b'),
    (AType: Argon2_id; Version: 19; MCost: 16384; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: '9cb75bd35e70794a40a31a41ae4aab8d28276c6f50f177ecd3392d5ef11145af'),
    (AType: Argon2_id; Version: 19; MCost: 16384; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: '53ab30848073d11e554876faa6fb26cd034f11e0c404e08aa8718398689444bc'),
    (AType: Argon2_id; Version: 19; MCost: 16384; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: 'd001c91eb61742d25950233848c19d8d0a75611f49b18daeae317dc30a70eff3'),
    (AType: Argon2_id; Version: 19; MCost: 65536; TCost: 1; Parallelism: 1;
     TagLen: 32; Tag: 'aa620846ec7ded087c052711975dd78d7adfef6ba03b92444e34bc56d9ce7426'),
    (AType: Argon2_id; Version: 19; MCost: 65536; TCost: 1; Parallelism: 2;
     TagLen: 32; Tag: 'b0d5cc958ab37e0e832b3961f11f29900f085058a024c9bb438ee03a9016d5b6'),
    (AType: Argon2_id; Version: 19; MCost: 65536; TCost: 1; Parallelism: 4;
     TagLen: 32; Tag: '03af5217aabd1f2669d3927adcb7587d0cd02944800c0a4242926d981bdd329d'),
    (AType: Argon2_id; Version: 19; MCost: 65536; TCost: 3; Parallelism: 1;
     TagLen: 32; Tag: '452a9bbce966abc041db3e64809acf0317c3280710beab146c549f373530fbee'),
    (AType: Argon2_id; Version: 19; MCost: 65536; TCost: 3; Parallelism: 2;
     TagLen: 32; Tag: '772b6d3428b4b6ff2cb6ae251ff750194070f3e918815a0ecf17a4060df5c353'),
    (AType: Argon2_id; Version: 19; MCost: 65536; TCost: 3; Parallelism: 4;
     TagLen: 32; Tag: '848d21c7a7f8a7967ea38a22a53adcab36b47b4046d059dd3216c5dbf737a1ce')
  );
