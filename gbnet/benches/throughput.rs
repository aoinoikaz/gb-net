use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use gbnet::{
    BitBuffer, BitDeserialize, BitSerialize, Channel, ChannelConfig, NetworkSerialize, Packet,
    PacketHeader, PacketType,
};
use std::hint::black_box;

#[derive(NetworkSerialize, Debug, PartialEq)]
struct PlayerUpdate {
    #[bits = 10]
    x: u16,
    #[bits = 10]
    y: u16,
    #[bits = 7]
    health: u8,
    moving: bool,
}

fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");

    let update = PlayerUpdate {
        x: 512,
        y: 768,
        health: 100,
        moving: true,
    };

    group.throughput(Throughput::Elements(1));

    group.bench_function("serialize", |b| {
        b.iter(|| {
            let mut buf = BitBuffer::new();
            black_box(&update).bit_serialize(&mut buf).unwrap();
            black_box(buf.into_bytes(true).unwrap());
        });
    });

    let mut buf = BitBuffer::new();
    update.bit_serialize(&mut buf).unwrap();
    let bytes = buf.into_bytes(true).unwrap();

    group.bench_function("deserialize", |b| {
        b.iter(|| {
            let mut buf = BitBuffer::from_bytes(black_box(bytes.clone()));
            black_box(PlayerUpdate::bit_deserialize(&mut buf).unwrap());
        });
    });

    group.finish();
}

fn bench_packet_encode_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet");

    let header = PacketHeader {
        protocol_id: 0x12345678,
        sequence: 42,
        ack: 41,
        ack_bits: 0xFFFF,
    };
    let payload = vec![0xABu8; 128];
    let packet = Packet::new(
        header,
        PacketType::Payload {
            channel: 0,
            is_fragment: false,
        },
    )
    .with_payload(payload);

    group.throughput(Throughput::Bytes(128));

    group.bench_function("serialize", |b| {
        b.iter(|| {
            black_box(packet.serialize().unwrap());
        });
    });

    let encoded = packet.serialize().unwrap();

    group.bench_function("deserialize", |b| {
        b.iter(|| {
            black_box(Packet::deserialize(black_box(&encoded)).unwrap());
        });
    });

    group.finish();
}

fn bench_channel_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("channel");

    let config = ChannelConfig::reliable_ordered();
    let msg = vec![0u8; 64];

    group.throughput(Throughput::Bytes(64));

    group.bench_function("send_receive", |b| {
        b.iter(|| {
            let mut sender = Channel::new(0, config);
            let mut receiver = Channel::new(0, config);

            sender.send(black_box(&msg), true).unwrap();
            let (_seq, wire) = sender.get_outgoing_message().unwrap();
            receiver.on_packet_received(wire);
            black_box(receiver.receive().unwrap());
        });
    });

    group.finish();
}

fn bench_fragmentation(c: &mut Criterion) {
    let mut group = c.benchmark_group("fragmentation");

    let data = vec![0xABu8; 4096];
    group.throughput(Throughput::Bytes(4096));

    group.bench_function("fragment", |b| {
        b.iter(|| {
            black_box(gbnet::fragment::fragment_message(1, black_box(&data), 1024).unwrap());
        });
    });

    let fragments = gbnet::fragment::fragment_message(1, &data, 1024).unwrap();

    group.bench_function("reassemble", |b| {
        b.iter(|| {
            let mut assembler =
                gbnet::FragmentAssembler::new(std::time::Duration::from_secs(5), 1024 * 1024);
            for frag in &fragments {
                assembler.process_fragment(frag);
            }
        });
    });

    group.finish();
}

fn bench_batching(c: &mut Criterion) {
    let mut group = c.benchmark_group("batching");

    let messages: Vec<Vec<u8>> = (0..20)
        .map(|i| format!("message {}", i).into_bytes())
        .collect();

    group.throughput(Throughput::Elements(20));

    group.bench_function("batch", |b| {
        b.iter(|| {
            black_box(gbnet::congestion::batch_messages(
                black_box(&messages),
                1200,
            ));
        });
    });

    let batches = gbnet::congestion::batch_messages(&messages, 1200);

    group.bench_function("unbatch", |b| {
        b.iter(|| {
            for batch in &batches {
                black_box(gbnet::congestion::unbatch_messages(black_box(batch)));
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_serialization,
    bench_packet_encode_decode,
    bench_channel_throughput,
    bench_fragmentation,
    bench_batching,
);
criterion_main!(benches);
